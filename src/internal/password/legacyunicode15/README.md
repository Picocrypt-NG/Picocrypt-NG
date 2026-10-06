# Historical legacy password normalization

This package preserves the exact Unicode 15 normalizer shipped in golang.org/x/text v0.41.0 with Go 1.26.6. It is used only to append decrypt candidates for legacy v1/v2 volumes. New encryption uses the current normalizer; PCV3 uses its separately frozen Unicode 17 implementation.

The upstream algorithm is intentionally unchanged, including historical composition behavior. For example, U+10041 followed by U+0300 previously normalized to U+00C0. Correcting that result here would make existing volume keys unreachable from their original typed password. These extra candidates are tried after current NFC, NFD and raw bytes and still require the existing volume authentication checks. The legacy deniability wrapper first probes the inner version; ordinary inner-volume authentication remains required.

The nine runtime files include the frozen Unicode 15 tables, totaling about 454 kB before package-name changes. Generators, alternate Unicode tables and upstream test infrastructure are excluded. BSD license is retained in LICENSE; provenance.json records source, module checksum, file hashes and the mechanical package/build-selector and reviewed lint-comment edits. Do not regenerate these historical tables from the current toolchain or import this package into a writer or PCV3 credential path.
