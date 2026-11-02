# PCV3 core model coverage

This map covers five critical-property blocks for Picocrypt NG Normal and D1.
Claims require a passing registered [EasyCrypt run](easycrypt/README.md) for the
current inputs. The [manifest](easycrypt/manifest.json) defines that run; model
and theorem counts do not measure application coverage.

| Block | Model claim and key theorems | Current public source anchors | Assumptions and open implementation relation |
| --- | --- | --- | --- |
| Record integrity and completeness | [RecordIntegrity](easycrypt/models/RecordIntegrity.ec): `record_integrity_reduction`. [NormalStream](easycrypt/models/NormalStream.ec): `stream_origin_reduction`, `accepted_exact_count`, `accepted_final_record`. A changed accepted stream yields a MAC forgery; supplied slots fix count/order/final. [D1RecordIntegrity](easycrypt/models/D1RecordIntegrity.ec): `d1_record_integrity_reduction`, `accepted_canonical_position`, `accepted_difference_extracts_byte_forgery`. | Normal [`expectedRecord`, `recordTag`, `readNormalRecords`](../src/internal/pcv3operation/internal/pcv3/records.go), [`readNormalVolumeWithProvider`](../src/internal/pcv3operation/internal/pcv3/normal_reader.go); D1 [`expectedD1OuterRecord`, `validateRecord`, `recordTag`](../src/internal/pcv3operation/internal/pcv3/d1_outer.go). | Normal starts from a valid supplied authenticated profile and one issued stream. D1 fixes one profile/MAC primitive and a supplied valid outer profile. Current Go profile construction, complete acceptance, physical-source stability, RS/padding and inner/outer composition remain separate. |
| Credential framing and context separation | [CredentialContext](easycrypt/models/CredentialContext.ec): `transcript_injective`, `schedule_info_injective`, `credential_hash_input_injective`, `d1_root_context_injective`, `normal_key_inputs_bind_context`. Equal encoded inputs bind their fields, purpose/domain, role and context arguments. | [`transcript.go`](../src/internal/pcv3operation/internal/pcv3credential/transcript.go), [`scheduleInfoFor` and Extract stages](../src/internal/pcv3operation/internal/pcv3credential/keys.go), [`d1ScheduleInfo`](../src/internal/pcv3operation/internal/pcv3credential/outer.go), [`d1InnerCredentialRoot`](../src/internal/pcv3operation/internal/pcv3credential/d1_inner.go). | This is input framing, before hash/KDF outputs. Factor admission, canonicalization/order, root selection and provenance are caller obligations. Distinct inputs do not imply distinct or independent derived keys. Normal root and VolumeID are Extract arguments, absent from Normal `info`. |
| Nonce and CTR domains | [RecordDomains](easycrypt/models/RecordDomains.ec): `record_nonce_distinct`, `record_used_intervals_disjoint`, `normal_record_parameters`, `normal_final_uses_no_counter`. Different valid record indices have distinct nonces and disjoint consumed Serpent counter intervals. | Normal [`expectedRecord`](../src/internal/pcv3operation/internal/pcv3/records.go); D1 [`recordParameters`](../src/internal/pcv3operation/internal/pcv3/d1_outer.go); [`PCV3WrapStandard1`, `PCV3WrapParanoid1`](../src/internal/pcv3operation/internal/pcv3crypto/stream.go). | One key/prefix context; 16-byte nonce prefix, 8-byte CTR prefix, index below `2^48`, record length at most 1 MiB. Callers must preserve those limits and prevent reuse across sessions. Library counter semantics and unused buffered keystream remain outside the model. |
| Construction confidentiality | [RecordConfidentiality](easycrypt/models/RecordConfidentiality.ec): `record_confidentiality_reduction`, `record_confidentiality_bound`; `cascade_confidentiality_reduction`, `cascade_confidentiality_bound`. Ciphertext/MAC publication preserves the base encryption LR bound, including length-preserving preprocessing before encryption. | [`writeNormalRecords`](../src/internal/pcv3operation/internal/pcv3/normal_writer.go); D1 [`sealRecord`, `recordTag`](../src/internal/pcv3operation/internal/pcv3/d1_outer.go); [`PCV3WrapParanoid1`](../src/internal/pcv3operation/internal/pcv3crypto/stream.go). | Equal-length messages, fresh 24-byte nonces, shared 16-byte cascade IV, independent ideal encryption/MAC/preprocessing keys and the base LR bound. Prefix, nonce, IV and length are allowed leakage; D1 computed metadata is conservatively public. Concrete cipher security, preprocessing length refinement, HKDF replacement, key-correlated metadata and D1 bootstraps remain open. No decryption oracle or CCA claim. |
| Read trust and operation authority | [ReadResultAuthority](easycrypt/models/ReadResultAuthority.ec): `archive_action_has_exact_read_history`, `callback_actions_are_one_shot`, `returned_callback_never_acts_again`, `publication_does_not_upgrade_trust`, `raw_selection_ignores_inner_success_and_publication`. [LifecycleAuthority](easycrypt/models/LifecycleAuthority.ec): `every_emitted_effect_has_ordered_history`, `no_read_force_presentation_or_receipt_authority`. | [`normalCompletion`](../src/internal/pcv3operation/internal/pcv3/normal_types.go), [`NativeReadOutput` and `runNativeReadSession`](../src/internal/pcv3operation/internal/pcv3/native_adapter.go), [`RecoveryResult`](../src/internal/pcv3operation/internal/pcv3/recovery_types.go), [`SourceDeletionAllowed`](../src/internal/pcv3operation/result.go). | Normal callback policy assumes trusted successful reader checks and output preparation. Recovery events consume validated immutable result tuples; selection and tuple validation remain external. The D1 emitter is a different interface. Read deletion denial is an interface constant; write lifecycle capability, public predicates and actual unlink effects require their separate relations. |

Normal's canonical profile has a separate empty final record. D1 outer records
use full non-final chunks and a sub-chunk final, which may contain data or be
empty after a full chunk. D1's actual outer MAC frame contains profile, index,
length, final byte and ciphertext; it contains no VolumeID. Its model proves
record forgery reduction and conditional stream properties, without proving
bootstrap selection, physical EOF or the complete inner/outer construction.
The outer plaintext reserves a 16-byte marker/length prefix; the profile model
constrains its extent, while its content and inner-volume validity remain open.
Ordinary D1 opening and strict [`VerifyD1`](../src/internal/pcv3operation/internal/pcv3/d1_verify.go)
have different validation contracts; the model does not equate them.

Paranoid writes Serpent-CTR before XChaCha20. The cascade theorem treats the
first stage as an arbitrary length-preserving map and transfers the outer
encryption's LR bound. It assumes no Serpent confidentiality property and makes
no security claim when the outer encryption's LR premise fails. The secrecy
reduction also needs no MAC security premise; integrity uses the separate MAC
forgery reduction.

Ordinary degraded reads and verified Force recovery can retain raw output
authority. Exact ordinary success is required for the modeled archive seal.
Raw-selected D1 stays unverified even if inner ranges authenticate. Publication
records a transport outcome and cannot upgrade that trust. Native preparation
failures can replace reader success before callback entry; those failures are
outside the result-preserving events. Archive follow-ups, encrypted-stream
actions, D1 emitters and filesystem publication need their own implementation
relations. The write lifecycle model consumes one logical deletion capability,
not one capability per unlink or a call to the reusable Go predicate.

The 19 models form these families:

- Framing and stream integrity: `RecordFraming`, `RecordIntegrity`, `NormalStream`,
  `D1RecordIntegrity`. `IndexOmissionReplay` is an intentionally defective replay
  witness under MAC correctness and lossless key generation.
- Normal profile construction and physical boundaries: `CanonicalRecords`,
  `CanonicalProfile`, `PayloadGeometry`, `CorePolicy`, `NormalConstructor`,
  `NormalPhysicalEOF`. The constructor's full success postcondition is a premise;
  the actual Go `expectedRecord` success/refusal proof remains open.
- Numeric representation: `BigEndianFields`, `SafeCastRepresentation`,
  `WordArithmetic`. These support the profile, domain and source-contract claims.
- Credentials and confidentiality: `CredentialContext`, `RecordConfidentiality`.
- Nonce/counter and authority policy: `RecordDomains`, `ReadResultAuthority`,
  `LifecycleAuthority`.

The separate [Gobra lane](gobra/README.md) checks 13 selected current Go helper
bodies: safe cast, record count, D1 parameter layout, three arithmetic wrappers,
payload/body/offset/metadata geometry, suite/core policy and the record geometry
guard. [Source correspondence](SOURCE-CORRESPONDENCE.md) states the conditional
joins to the mathematical models. Standard-library interfaces, integer/byte and
shift interpretations, compiler/frontend semantics and cross-logic composition
retain their stated trust boundaries. These contracts do not prove the complete
reader, writer, credential lifecycle or application.

Common caller and primitive obligations remain explicit:

- Cryptographic hash collision resistance, the chosen MAC's UF-CMA security,
  primitive nonce-respecting LR security, and Argon2id/HKDF assumptions must
  justify their concrete uses. Purpose labels alone establish no output-key
  independence. Secret entropy, independent key/root generation and correct
  authenticated key/context selection remain external.
- The frozen password profile, factor admission, keyfile hashing and canonical
  ordering must supply the bytes modeled by `CredentialContext`. The model does
  not prove normalization, sorting, secret ownership or runtime zeroing.
- Callers must establish authenticated geometry and context, correct prefix and
  nonce generation, per-key global nonce discipline, source stability and the
  boundary between authenticated results and unverified recovery.

Semantic controls exercise omitted indices/roles, weakened stream count/order/
final guards, CTR overlap, EOF/RS boundaries and degraded archive authority.
The plaintext-wrapper control is a separate leak witness. Controls validate
specific model claims; they do not establish a production exploit or runtime
coverage. Admission, EOF-closure, source-binding and runner tests protect the
verification tooling and remain a separate evidence class.

Full Go/Kotlin/JavaScript refinement, OS/provider behavior and implementations of
cryptographic primitives are outside this core-model task. Legacy v1/v2,
frontend/runtime information flow, crash behavior, release authority and complete
D1 bootstrap/inner/outer composition retain their own review and test evidence.
Each row leaves a specific model-to-source relation open. These results do not
establish that the whole core or application is fully proved.
