# TEST ONLY recovery artifacts

These files are literal hexadecimal encodings assembled from the frozen
application-artifact schema. They were not produced by the production encoder.

- `partial.hex` is a five-byte verified record with a missing final record.
- `unverified.hex` is one explicitly consented six-byte unverified record from
  the backup capsule role, with a missing final record.

Both use the exact 80-byte header, one 40-byte range entry, contiguous data at
absolute offset 120, and exact physical EOF.

The malformed-table tests protect these production risks:

- Version, schema, flag, and reserved-byte mutations prevent silent future
  semantics from being treated as this frozen schema.
- Count and fixed-offset mutations prevent attacker-controlled allocation,
  table aliasing, and segment exposure before complete layout validation.
- Gap, status, segment-offset, and reserved-byte mutations prevent evidence
  attribution from being erased or data from being assigned to missing ranges.
- Total-length and trailing-byte mutations preserve exact EOF as part of the
  canonical physical layout.
