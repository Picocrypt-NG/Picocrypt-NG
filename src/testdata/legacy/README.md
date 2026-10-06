# Legacy reference source

`original_audited_picocrypt.go` contains archived upstream **v1.49** source.
The filename is historical; it does not establish that this exact version was
audited. This reference file is not part of the application build.

The 2024 Radically Open Security audit covered upstream commit
`7e403a2e57d3f639e00bd82e356cd393e646fe01`, whose source declares **v1.40**.
That audit does not automatically cover the archived v1.49 source, later
Picocrypt NG v2 changes, or PCV3.

Keep this source unchanged when comparing legacy behavior. The
[golden fixtures](../golden/) protect compatibility; the maintained
implementations are under `src/internal/`. See the
[review policy](../../../CONTRIBUTING.md#ai-assistance) for audit scope.
