# PCV3 core assurance

These checks cover the five practical PCV3 contracts in the
[coverage map](COVERAGE.md): integrity/completeness, credential and key-context
framing, nonce/counter separation, construction confidentiality and result
authority. They do not establish whole-application refinement, an independent
security audit or cryptographic strength of the concrete primitives.

- [EasyCrypt models](easycrypt/README.md) check byte framing, record/session
  origin reductions, canonical stream profiles, nonce/counter domains,
  normal/RS record extents, structural core policy, reduced lifecycle policy,
  integer representation and the Normal reader's final EOF observation policy.
  Credential framing, D1 outer-record integrity and conditional confidentiality
  reductions complement the Normal stream and read-result authority models.
  Model statements, primitive assumptions and implementation relations remain
  separate. The Normal constructor model identifies the canonical record from
  its full success postcondition; obtaining that postcondition from the actual
  Go constructor remains an open obligation.
- [Go source contracts](gobra/README.md) check the actual current
  `SafeUint64ToInt64`, `canonicalRecordCount` and D1 `recordParameters` bodies
  and the three checked-arithmetic helpers with Gobra, without changing
  production source. The normal/inner payload and encoded-body helpers are
  checked with their actual dependencies, as is the full-domain record-offset
  helper. Metadata geometry preserves its original named results and full
  `uint32` input domain. Arithmetic and parametric array-layout claims have
  distinct modes and trusted interfaces. Structural core and record-geometry
  guards use composable Boolean contracts with an erased ghost observation;
  raw string/bit interpretations remain separate. Their
  contracts are paired with separate EasyCrypt representation lemmas.
- [Source correspondence](SOURCE-CORRESPONDENCE.md) states the bounded
  conditional composition argument and its trusted interfaces. This is a
  reviewed contract relation, not automatic cross-language proof transport.

The maintained commands are also described in
`.github/workflows/verify-easycrypt-models.yml`. Proof caches, generated code and
runtime evidence are ignored. Tooling-policy and source-identity tests are not
application-behavior coverage.

The coverage map names each source relation, primitive assumption and open
boundary. Full language/runtime and OS refinement, concrete primitive proofs,
complete D1 bootstrap/inner/outer composition and legacy/frontend behavior are
outside this core-model result. Their existing tests and review evidence remain
separate from the model proofs.
