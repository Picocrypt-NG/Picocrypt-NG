# PCV3 normal-volume public test data

Every file here is deterministic TEST ONLY data. Nothing is secret or operational. `manifest.json` is a standalone public reader-test index containing only the fields and blobs documented below.

The `volume` file is the canonical probe/inspect source and is bound by exact size and SHA-256. Small plaintexts and all credential factors are exact blobs. Large plaintexts use an exact repeated-byte recipe plus size and SHA-256. Keyfile array order is significant.

The suffix and extra-byte fixtures keep the canonical volume through Probe, Inspect, and the bounded pre-KDF revalidation. The declared `session_view` switches on the first metadata read after that revalidation. Their two authenticated capsules belong to that frozen session contract. A static appended-source reader check may reuse the public `a5` sentinel, but it is a separate contract.

| Fixture | Volume bytes | Volume SHA-256 | Plaintext | Selected role | Expected |
|---|---:|---|---|---|---|
| `normal-standard-password-only-small` | 2353 | `4021b80c8f8a435b60d356134116baa24efb6211afcf5a7e31702d40c5e98be5` | `file:9` | `primary` | `success / none` |
| `normal-standard-combined-ordered-empty` | 2232 | `9d41537f4fbcf4ca1ca517a899ae191ae28abde592b9d0c811e9e1b5fa9f6f47` | `file:0` | `primary` | `success / none` |
| `normal-standard-combined-ordered-one` | 2345 | `6c7f4519612e5767c55b2d5713f483b95eccb8f85969d4445cba7a72744f28f8` | `file:1` | `primary` | `success / none` |
| `normal-standard-combined-ordered-before-mib` | 1050919 | `261f756bb7f5b5882ea9050a7562dc480bc67823af7e15295a75221ffef2dd6e` | `repeat:1048575x03` | `primary` | `success / none` |
| `normal-standard-combined-ordered-exact-mib` | 1050920 | `deeb5e3b6adbb85e14f70454c96d508a5105127e99b251ff8b0b2cae0e06399d` | `repeat:1048576x04` | `primary` | `success / none` |
| `normal-standard-combined-ordered-after-mib` | 1051033 | `b0394467df4331f70d39b15d68909b0fccbf1ba53cba5d25dc397974e64c47ba` | `repeat:1048577x05` | `primary` | `success / none` |
| `normal-standard-combined-ordered-two-mib` | 2099608 | `5845cf7585fb85f5e48d20b9c0e2a075355190e2bb9445217f455bca31fcc9da` | `repeat:2097152x06` | `primary` | `success / none` |
| `normal-standard-keyfiles-only-small` | 2361 | `3df9940425d3cc00825d403b4b81595b0ef215d387ffc0a9a4c38b84e24fb0dd` | `file:17` | `primary` | `success / none` |
| `normal-standard-combined-unordered-rs-small` | 2488 | `0e72c6b980369851e4fcd83e3a07003cc1b79596d49d59210f256d4729b8e6db` | `file:33` | `primary` | `success / none` |
| `normal-paranoid-combined-unordered-rs-small` | 2624 | `2c0d508e1da532ff9826e74a9ba97ef5ece161a052c05c963286e610f8a8b480` | `file:65` | `primary` | `success / none` |
| `normal-degraded-capsule` | 2361 | `f7883ee171f0a9a30f5f6817c30034eed8426560667da3055063653ab86b2adc` | `file:17` | `backup` | `authenticated-degraded / capsule-rs` |
| `normal-degraded-metadata` | 2361 | `e053fd8253456b8dcdc1b56d70bca0ef2f8cd9f375a73790b222022554d100e8` | `file:17` | `primary` | `authenticated-degraded / metadata` |
| `normal-degraded-trailer` | 2361 | `705f4256e3593b8275ff3a5cc59a591a15cb4e057b03fea5673c6702a152f81d` | `file:17` | `primary` | `authenticated-degraded / tail-geometry` |
| `normal-negative-descriptor` | 2361 | `5513b16cdd977b0f07bfe4965596ca577a419137319e96f22f4a7981db12cc41` | `file:17` | `primary` | `authentication-failed / descriptor` |
| `normal-negative-record` | 2361 | `48fb15ee38dd96f1d76370474da449cdb79cf1080e2bd3215d631f19a3a44c81` | `file:17` | `primary` | `authentication-failed / record-auth` |
| `normal-negative-final` | 2361 | `111cd3040ceaedd0c68e25a897d6ccc26e53d6d3165049c7b8b3abe212ffa7f8` | `file:17` | `primary` | `authentication-failed / final-record` |
| `normal-negative-suffix` | 2361 | `537a51f160abf16fb9db89f4126b167678fb1cdcd3e00c98414dd6b85a10c751` | `file:17` | `primary` | `authentication-failed / tail-geometry` |
| `normal-negative-extra-byte` | 2361 | `65e23908d2c2d4d5c5ae3a3d6d0f991c30a2f1cb793fc1024632b4cfbadf300c` | `file:17` | `primary` | `authentication-failed / tail-geometry` |
