# Changelog

## [Unreleased]

### Added

* dynamic option for submission
* wait option for get result by uuid
* `waitForUUID` polling loop in detect mode now uses the server-side `?wait=` parameter, reducing unnecessary round-trips.

## [v1.6.1]

### Fixed

* Fix syndetect analysis ID lookup in cached result polling

## [v1.6.0]

### Added

* ClientConfig + NewClientFromConfig

### Changed

* Reconfigure now accept ClientConfig

## [v1.5.0] - 2025-10-01

### Added

* add export result capability
* [pkg] Add interfaces to use gdetect client in a managed connector

## [v1.4.1] - 2025-09-22

* [pkg] replace buffer by reader in waitForReader
* upgrade go version to 1.24

## [v1.4.0] - 2024-10-23

### Added

* [pkg] Add malware threshold to get status result
* [pkg] preget result with sha256 for waitfor method if bypass-cache is not set

## [v1.3.0] - 2024-10-08

### Added

* [cli/pkg] Add syndetect support

## [v1.2.2] - 2024-04-22

### Added

* [pkg] Add special status to result

## [v1.2.1] - 2024-04-15

### Added

* [pkg] Add mock for gdetect

## [v1.2.0] - 2023-11-21

Compatible with GLIMPS Malware 3.1.2 (for the extract archive password option)

### Added

* [cli/pkg] Extract password option for submit and waitfor

## [v1.1.0] - 2023-10-30

### Added

* [cli] Get profile status
* [pkg] Option to specify filename at submission
* [pkg] Method to retrieve full submission
* [pkg] Get profile status

### Changed

* [pkg] Use http client
* [pkg] Better token validation
* Enhance github action jobs
    * Add staticcheck and gofumpt

## [v1.0.0] - 2022-12-06

### Added

* First client and library version
