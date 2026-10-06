# Getting started with Picocrypt NG

Start with these maintained documents:

- [README](../README.md): product features and platform support.
- [Architecture](../ARCHITECTURE.md): package boundaries and data flow.
- [Source build and tests](../src/README.md): Go 1.27.1 setup and verification lanes.
- [Android development](../android/README.md): Kotlin host, gomobile and device checks.
- [Contribution guidelines](../CONTRIBUTING.md): changes, tests and review policy.
- [PCV3 security contract](SECURITY_CONTRACT.md): required properties and evidence.
- [CLI](../CLI.md) and [internal APIs](../API.md): command and maintainer contracts.
- [Cryptographic internals](../Internals.md): legacy format details and labelled PCV3 notes.

Native PCV3 operations enter through `src/internal/pcv3operation/`; its private
packages implement credentials, codecs and recovery. Publication and cleanup
ownership also involve `src/internal/pcv3publication/`. Legacy v1/v2 compatibility
uses the separate `volume`, `crypto`, `header` and `keyfile` paths.

Desktop, CLI, Android and browser/WASM have different feature contracts. Follow
the relevant frontend and its tests; a shared primitive does not imply identical
behavior. Before changing a security-sensitive path, trace its callers, result
handling and cleanup, and identify the compatibility evidence it must preserve.
