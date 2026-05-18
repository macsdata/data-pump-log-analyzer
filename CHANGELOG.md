# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.1] - 2026-05-18

### Fixed
- SyntaxWarning: "\d" in newer python releases

## [1.0.0] - 2026-03-11

### Fixed
- #3, Wrong sorting order for worker id
- Changed non breaking space in html report
- Removed duplicate updateRowStyles function
- Fixed search/filter in html report
- Added utf-8 encoding when reading the log file 

## [0.9.3] - 2025-04-24

### Fixed
- #1, UnicodeEncodeError on Windows
- #2, HTML report not showing table details (rows, size, seconds, partitions, ...)

### Changed
- Primary color for light and dark theme

## [0.9.2] - 2024-09-01

### Added
- Initial release of Data Pump Log Analyzer.
- Command-line interface with various analysis modes.
- Filtering, Sorting and Row limit options.
- Export report to text or html format.
