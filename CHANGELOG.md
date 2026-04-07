# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-07
### Added
- Added `remediation_cli.py` for automated security patching.
- Implementation of `security_edge_cases.py` for deeper testing.
- Added `Makefile` for automated build and test orchestration.

## [1.1.0] - 2026-04-03
### Added
- Multi-threaded Rust Forensic Engine (v4.0).
- Parallel log scanning with `std::thread`.
- ANSI color support for CLI reports.

### Changed
- Refactored Flask middleware to use `hmac.compare_digest`.
- Improved Nginx log scrubbing filters.

## [1.0.0] - 2026-03-28
### Added
- Initial project structure.
- Basic Flask application with insecure "Token in Query Params" route.
- Docker and Docker Compose configuration.
- Nginx reverse proxy implementation.
- Basic README documentation.

## [0.1.0] - 2026-03-17
### Added
- Initial repository setup.
- Basic security analysis notes.
