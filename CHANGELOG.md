# Changelog

## [v1.6.7]

### Changed

* `WaitForReader` reuses temp files from a pool and streams the body with a pooled buffer, avoiding a `CreateTemp`/`Remove` syscall pair and a copy-buffer allocation per request. `Client.Close` releases the pooled files.

### Fixed

* `WaitForReader` hashes while buffering to the temp file and reuses that hash for the preget cache lookup, removing the second full read pass over the temp file per request.

## [v1.6.6]

## Added

* `ClientConfig.TransportWrapper` to decorate the library-built HTTP transport.

### Changed

* /status change in gmapi v3.54.0 daily quota is replaced with monthly quota and parallel quota.

## [v1.6.5]

### Added

* http client: idle pool is now configurable.

### Fixed

* errors: returned errors are more clear about which step failed.

## [v1.6.4]

### Fixed

* `WaitForReader` no longer submits the SHA256 of an empty file: `waitforWithPreGet` now seeks to the start of the buffered reader before hashing, so the cache lookup uses the actual content hash.

## [v1.6.3]

### Fixed

* Fix GetResultByUUID for syndetect

## [v1.6.2]

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
