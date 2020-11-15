# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add changelog ([#19](https://github.com/ranweiler/pete/pull/19))

### Changed

- `Ptracer::spawn()` now takes a `std::process::Command` ([#21](https://github.com/ranweiler/pete/pull/21))
- Remove `cmd` module and custom `Command` struct
- Updated `nix` dependency to 0.19.0

## [0.3.1] - 2020-11-14

### Fixed

- Handle attach-stops delivered before ptrace-event-stops ([#12](https://github.com/ranweiler/pete/pull/12))

- Register new tracee in `vfork` event handler (from [@travitch](https://github.com/travitch), [#8](https://github.com/ranweiler/pete/pull/8))

## [0.3.0] - 2020-08-13

### Added

- Enable setting `Command` environment ([#6](https://github.com/ranweiler/pete/pull/6))

### Changed

- `Ptracer::spawn()` now accepts a `Command` instead of an arg vector ([#6](https://github.com/ranweiler/pete/pull/6))

### Fixed

- Prevent `Tracee` from auto-deriving `Send` ([`23d7765`](https://github.com/ranweiler/pete/commit/23d77651f4badec449109aa7c02f97e768297bcb))
