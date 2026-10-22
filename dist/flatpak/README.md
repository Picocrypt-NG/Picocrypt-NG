The reusable `go-toolchain.yaml` module supplies Go 1.27.3 from the official
architecture-specific archives. It uses `/app/lib/sdk/golang` during the build
and removes its installed files during Flatpak cleanup. It does not replace the
SDK's `/usr/lib/sdk/golang` or change the host's mise installation.
Use the complete builder pipeline before exporting; `--build-only` retains build
dependencies.

For a manifest maintained in a separate packaging repository, copy this module
beside the manifest and include it before the Picocrypt NG module:

```yaml
build-options:
  prepend-path: /app/lib/sdk/golang/bin
  env:
    GOROOT: /app/lib/sdk/golang
    GOTOOLCHAIN: local
    GOPROXY: "off"
    CGO_ENABLED: "1"
modules:
  - go-toolchain.yaml
  # Existing Picocrypt NG module follows.
```

Remove the now-unused `org.freedesktop.Sdk.Extension.golang` entry. Before the
application's existing build commands, require
`test "$("$GOROOT/bin/go" env GOVERSION)" = go1.27.3`. Keep the application's
existing architecture and X11/Wayland builds, and its vendored dependency sources
with `-mod=vendor`. `GOTOOLCHAIN=local` rejects an incompatible Go requirement
instead of downloading another toolchain; `GOPROXY=off` prevents module downloads.

Flatpak Builder downloads and verifies the pinned archive during source
preparation. After sources are cached, `flatpak-builder --disable-download`
also makes source availability explicit for an offline build. Keep source
archives and vendored dependencies in the packaging source cache; do not use a
recursive copy of a local checkout as a release source.

This module does not change the external Flathub manifest, select a release tag,
or refresh its vendored dependencies. Packaging maintainers must perform those
steps and validate the complete application build separately. Update both
archive URLs, hashes, and version checks together when the project's pinned Go
version changes.
