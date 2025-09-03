# Changelog

All notable changes to the Enhanced Package Security Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.1] - 2025-09-03

### Fixed
- Fixed script exiting prematurely when no AUR packages need updating
- Fixed `wait` command causing script exit due to `set -e` when yay times out or fails
- Fixed `grep -c` command causing script exit when no matches are found
- Script now correctly continues with official repository updates even when AUR checking fails

## [2.1.0] - 2025-08-23

### Added
- **Post-Update Analysis System**: Automatic system state analysis after package updates
- **AI-Powered Issue Detection**: Claude identifies failed services, dependency conflicts, and configuration issues
- **Planning Mode Integration**: Review and approve fixes before execution for maximum safety
- **Automated Fix System**: Apply fixes automatically or with manual confirmation
- **Comprehensive System Checks**: 
  - Failed systemd services detection
  - Configuration file conflicts (.pacnew files)
  - Broken package dependencies
  - Orphaned packages identification
  - Kernel error message analysis
- **Fix Execution Modes**:
  - Manual mode (default): Confirm each fix individually
  - Auto mode: Apply fixes automatically with warning
  - Skip mode: Analysis only without fixes
- **Detailed Fix Logging**: All actions logged for audit and potential rollback
- **New Command-Line Options**:
  - `--skip-post-update`: Skip post-update analysis entirely
  - `--fix-mode=MODE`: Choose fix execution mode (auto/manual/skip)
  - `--post-update-model=MODEL`: Select Claude model for post-update analysis

### Changed
- Version updated from 2.0 to 2.1
- Enhanced update process to capture output for analysis
- Improved error handling and reporting

### Technical Details
- Integrated `claude --permission-mode plan` for safe fix proposals
- Added comprehensive system information collection
- Implemented structured Claude prompts for issue categorization
- Added fix plan generation and execution system

## [2.0.0] - 2025-08-15

### Added
- **Binary Pattern Scanning**: Scans pre-built binaries for suspicious URLs and crypto wallets
- **Official Package Review**: Optional security review of official repository packages
- **Smart Risk Assessment**: Improved categorization (NONE/LOW = safe, MEDIUM = warning, HIGH/CRITICAL = blocked)
- **Remediation Suggestions**: Claude provides specific steps to fix security issues
- **Selective Review**: Choose specific packages to review instead of all-or-nothing approach
- **Parallel Scanning**: Support for parallel security scans with configurable job count
- **Package Display Limits**: Control how many packages to display with `--max-display`

### Fixed
- False positive detection for pre-built binaries from official sources
- Package detection issues with repository identification
- Timeout handling for AUR update checks

### Changed
- Improved security policies based on repository trust levels
- Enhanced malware pattern detection
- Better handling of binary files in packages
- More accurate risk level categorization

### Performance
- Added configurable parallel scanning (default: 10 jobs)
- Optimized Claude model selection (haiku by default for speed)
- Improved package fetching with timeout protection

## [1.0.0] - Initial Release

### Features
- Basic AUR package security scanning
- Claude AI integration for malware detection
- Pre-update security gating
- Security report generation
- Support for multiple Claude models (haiku/sonnet/opus)

### Security Checks
- PKGBUILD analysis
- Shell script scanning
- URL validation
- Command pattern detection
- Obfuscation detection

## Migration Guide

### From v2.0 to v2.1
No breaking changes. New features are opt-in:
- Post-update analysis runs by default but can be disabled with `--skip-post-update`
- Fix mode defaults to "manual" for safety
- All existing command options remain compatible

### From v1.0 to v2.0
- Update script to latest version
- Review new command-line options
- Consider using `--model=haiku` for faster scans
- Test selective review feature for better control

## Known Issues

### v2.1
- Post-update analysis may take additional time on systems with many services
- Planning mode requires interactive terminal
- Some complex configuration conflicts may require manual intervention

### v2.0
- Binary scanning may increase scan time for large packages
- Some edge cases in package name resolution for chaotic-aur

## Future Roadmap

### Planned for v2.2
- [ ] Rollback capability for failed fixes
- [ ] Integration with system snapshots (timeshift/snapper)
- [ ] Custom fix scripts repository
- [ ] Web dashboard for analysis reports

### Planned for v3.0
- [ ] Machine learning-based threat detection
- [ ] Community threat intelligence sharing
- [ ] Automated security policy updates
- [ ] Integration with upstream security advisories

## Support

For issues, feature requests, or questions:
- GitHub Issues: [Report issues here](https://github.com/yourusername/arch-security-wrapper/issues)
- Documentation: See README.md for detailed usage instructions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Claude AI by Anthropic for powering the security analysis
- Arch Linux community for package management tools
- Contributors and testers who helped improve the scanner