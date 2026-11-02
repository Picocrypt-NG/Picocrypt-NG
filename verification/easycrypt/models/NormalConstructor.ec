require import AllCore IntDiv List.
require import RecordFraming BigEndianFields CanonicalRecords CanonicalProfile.
require import NormalStream.
require import RecordDomains PayloadGeometry CorePolicy SafeCastRepresentation.

type expectation_view = {
  ev_index : int;
  ev_final : bool;
  ev_plaintext_offset : int;
  ev_ciphertext_length : int;
  ev_descriptor : bytes;
  ev_descriptor_offset : int;
  ev_body_offset : int;
  ev_encoded_body_length : int;
  ev_nonce : bytes;
  ev_serpent_iv : bytes
}.

op expectation_domain (record : expectation_view) : bool =
  uint64_domain record.`ev_index /\ uint64_domain record.`ev_plaintext_offset /\
  uint64_domain record.`ev_ciphertext_length /\
  int64_domain record.`ev_descriptor_offset /\ int64_domain record.`ev_body_offset /\
  int64_domain record.`ev_encoded_body_length /\
  size record.`ev_descriptor = 16 /\ size record.`ev_nonce = 24 /\
  size record.`ev_serpent_iv = 16.

op constructor_length_source (length count index : int) : int =
  if index = count then 0 else
    if length - index * 1048576 < 1048576 then length - index * 1048576 else 1048576.

(* The numeric source predicate omits magic; success supplies that observation.
   Existing source-ghost representation lemmas normalize Count/Total/Offset. *)
op constructor_numeric_input (core : core_view) (geometry : geometry_view) index
    (mask_clear serpent_zero rs_bit : bool) : bool =
  source_core_policy core true mask_clear serpent_zero /\
  0 <= geometry.`gv_front_header_length /\ 0 <= geometry.`gv_payload_length /\
  0 <= geometry.`gv_backup_capsule_offset /\
  geometry.`gv_record_count = core.`cv_record_count /\
  geometry.`gv_payload_body_rs = rs_bit /\
  geometry.`gv_front_header_length = core.`cv_front_header /\
  geometry.`gv_payload_length = rgm_payload_total core.`cv_plaintext_length geometry.`gv_payload_body_rs /\
  geometry.`gv_backup_capsule_offset = geometry.`gv_front_header_length + geometry.`gv_payload_length /\
  index <= core.`cv_record_count.

op descriptor_octet_contract (encoded : bytes) index length is_final : bool =
  size encoded = 16 /\
  (forall j, 0 <= j < 8 =>
    from_be [nth (byte_of_int 0) encoded j] = octet64 index j) /\
  (forall j, 0 <= j < 4 =>
    from_be [nth (byte_of_int 0) encoded (8+j)] = octet64 length (j+4)) /\
  nth (byte_of_int 0) encoded 12 = (if is_final then byte_of_int 1 else byte_of_int 0) /\
  nth (byte_of_int 0) encoded 13 = byte_of_int 0 /\
  nth (byte_of_int 0) encoded 14 = byte_of_int 0 /\
  nth (byte_of_int 0) encoded 15 = byte_of_int 0.

lemma constructor_length_canonical length count index :
  count = canonical_count length =>
  constructor_length_source length count index = record_body_length length index.
proof.
  move=> ->.
  by rewrite /constructor_length_source /record_body_length /chunk_length /chunk_size; smt().
qed.

lemma constructor_numeric_implies_source_guard core geometry index mask_clear serpent_zero rs_bit :
  core_domain core => geometry_domain geometry =>
  constructor_numeric_input core geometry index mask_clear serpent_zero rs_bit =>
  rgm_source_policy core geometry true mask_clear serpent_zero rs_bit.
proof.
  rewrite /core_domain /geometry_domain /constructor_numeric_input
    /rgm_source_policy /source_core_policy /rgm_payload_valid
    /int64_domain /min_int64 /max_int64 /uint64_modulus.
  smt().
qed.

lemma descriptor_octets_determine_encoding encoded index length is_final :
  0 <= length < 4294967296 =>
  descriptor_octet_contract encoded index length is_final =>
  encoded = be64 index ++ descriptor_tail length is_final.
proof.
  move=> hl [hs [hindex [hlength [hflag [hz1 [hz2 hz3]]]]]].
  apply (eq_from_nth (byte_of_int 0)); first by rewrite size_cat size_be64 size_descriptor_tail; smt().
  move=> j hj.
  have hj16 : 0 <= j < 16 by smt().
  case (j < 8) => hj8.
  + rewrite nth_cat size_be64 hj8 /=.
    apply byte_numeric_injective.
    have ha := hindex j _; first by smt().
    have hb := be64_octet index j _; first by smt().
    by smt().
  rewrite nth_cat size_be64 hj8 /=.
  case (j < 12) => hj12.
  + rewrite /descriptor_tail nth_cat size_be32 (_ : j - 8 < 4) 1:/# /=.
    apply byte_numeric_injective.
    have ha := hlength (j-8) _; first by smt().
    have hb := be32_low_octet64 length (j-8) hl _; first by smt().
    by smt().
  have hc : j = 12 \/ j = 13 \/ j = 14 \/ j = 15 by smt().
  by case: hc=> [->|[->|[->|->]]];
    rewrite /descriptor_tail nth_cat size_be32 /=; smt().
qed.

op constructor_scalar_post (core : core_view) (geometry : geometry_view) index
    (record : expectation_view) : bool =
  record.`ev_index = index /\ record.`ev_final = (index = core.`cv_record_count) /\
  record.`ev_plaintext_offset = (if index = core.`cv_record_count then core.`cv_plaintext_length else index*1048576) /\
  record.`ev_ciphertext_length = constructor_length_source core.`cv_plaintext_length core.`cv_record_count index /\
  record.`ev_descriptor_offset = geometry.`gv_front_header_length +
    offset_math core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs index /\
  record.`ev_body_offset = record.`ev_descriptor_offset + 48 /\
  record.`ev_encoded_body_length = encoded_body_length geometry.`gv_payload_body_rs record.`ev_ciphertext_length /\
  0 <= record.`ev_descriptor_offset /\ 0 <= record.`ev_body_offset /\
  record.`ev_body_offset + record.`ev_encoded_body_length <= geometry.`gv_backup_capsule_offset /\
  (record.`ev_final => record.`ev_body_offset + record.`ev_encoded_body_length = geometry.`gv_backup_capsule_offset).

op constructor_nonce_post (core : core_view) index (record : expectation_view) : bool =
  (forall j, 0 <= j < 16 => nth (byte_of_int 0) record.`ev_nonce j =
    nth (byte_of_int 0) core.`cv_xnonce_prefix j) /\
  (forall j, 0 <= j < 8 => from_be [nth (byte_of_int 0) record.`ev_nonce (16+j)] = octet64 index j).

op constructor_iv_post (core : core_view) shifted (record : expectation_view) : bool =
  (core.`cv_suite = 2 =>
    forall j, 0 <= j < 8 =>
      nth (byte_of_int 0) record.`ev_serpent_iv j = nth (byte_of_int 0) core.`cv_serpent_prefix j /\
      from_be [nth (byte_of_int 0) record.`ev_serpent_iv (8+j)] = octet64 shifted j) /\
  (core.`cv_suite <> 2 => record.`ev_serpent_iv = nseq 16 (byte_of_int 0)).

(* This is the success projection of the complete source postcondition.
   Its availability from actual Go verification is a separate obligation. *)
op constructor_success_post (core : core_view) (geometry : geometry_view) index
    (error_is_nil magic_equal mask_clear serpent_zero rs_bit : bool) shifted
    (record : expectation_view) : bool =
  error_is_nil /\ magic_equal /\
  constructor_numeric_input core geometry index mask_clear serpent_zero rs_bit /\
  constructor_scalar_post core geometry index record /\
  descriptor_octet_contract record.`ev_descriptor index record.`ev_ciphertext_length record.`ev_final /\
  constructor_nonce_post core index record /\ constructor_iv_post core shifted record.

op canonical_expectation (core : core_view) (geometry : geometry_view) index : expectation_view = {|
  ev_index = index;
  ev_final = index = canonical_count core.`cv_plaintext_length;
  ev_plaintext_offset = if index = canonical_count core.`cv_plaintext_length then core.`cv_plaintext_length else index*chunk_size;
  ev_ciphertext_length = record_body_length core.`cv_plaintext_length index;
  ev_descriptor = be64 index ++ descriptor_tail (record_body_length core.`cv_plaintext_length index)
    (index = canonical_count core.`cv_plaintext_length);
  ev_descriptor_offset = descriptor_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index;
  ev_body_offset = body_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index;
  ev_encoded_body_length = encoded_body_length geometry.`gv_payload_body_rs (record_body_length core.`cv_plaintext_length index);
  ev_nonce = record_nonce core.`cv_xnonce_prefix index;
  ev_serpent_iv = if core.`cv_suite = 2 then serpent_iv core.`cv_serpent_prefix index else nseq 16 (byte_of_int 0)
|}.

lemma constructor_success_count_index_length core geometry index en me mc sz rs shifted record :
  core_domain core => uint64_domain index =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  core.`cv_record_count = canonical_count core.`cv_plaintext_length /\
  0 <= index <= canonical_count core.`cv_plaintext_length /\
  record.`ev_ciphertext_length = record_body_length core.`cv_plaintext_length index /\
  0 <= record.`ev_ciphertext_length <= chunk_size.
proof.
  move=> hd hi hp.
  have hl : uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /uint64_domain /uint64_modulus; smt().
  have hn : constructor_numeric_input core geometry index mc sz rs.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hs : constructor_scalar_post core geometry index record.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hc := canonical_count_quotient core.`cv_plaintext_length hl.
  have hcount : core.`cv_record_count = canonical_count core.`cv_plaintext_length.
  + by move: hn hc; rewrite /constructor_numeric_input /source_core_policy /chunk_size; smt().
  have hindex : 0 <= index <= canonical_count core.`cv_plaintext_length.
  + by move: hi hn; rewrite /uint64_domain /constructor_numeric_input; smt().
  have he := constructor_length_canonical core.`cv_plaintext_length core.`cv_record_count index hcount.
  have hb := record_body_bounds core.`cv_plaintext_length index hl hindex.
  by move: hs; rewrite /constructor_scalar_post; smt().
qed.

lemma constructor_success_nonce core geometry index en me mc sz rs shifted record :
  core_domain core => expectation_domain record =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  record.`ev_nonce = record_nonce core.`cv_xnonce_prefix index.
proof.
  move=> hd hr hp.
  have hs : size core.`cv_xnonce_prefix = 16 by move: hd; rewrite /core_domain; smt().
  have hn : size record.`ev_nonce = 24 by move: hr; rewrite /expectation_domain; smt().
  have hc : constructor_nonce_post core index record.
  + by move: hp; rewrite /constructor_success_post; smt().
  rewrite /record_nonce.
  apply (prefix_octet_contract_determines_encoding core.`cv_xnonce_prefix record.`ev_nonce index).
  + by smt().
  + by move: hc; rewrite /constructor_nonce_post hs; smt().
  by move: hc; rewrite /constructor_nonce_post hs; smt().
qed.

lemma constructor_success_iv core geometry index en me mc sz rs shifted record :
  core_domain core => expectation_domain record =>
  (core.`cv_suite = 2 => shifted = go_u64_shift16 index) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  record.`ev_serpent_iv = if core.`cv_suite = 2 then serpent_iv core.`cv_serpent_prefix index
    else nseq 16 (byte_of_int 0).
proof.
  move=> hd hr hshift hp.
  have hc : constructor_iv_post core shifted record.
  + by move: hp; rewrite /constructor_success_post; smt().
  case (core.`cv_suite = 2) => hs /=; last by move: hc; rewrite /constructor_iv_post; smt().
  have hpref : size core.`cv_serpent_prefix = 8 by move: hd; rewrite /core_domain; smt().
  have hout : size record.`ev_serpent_iv = 16 by move: hr; rewrite /expectation_domain; smt().
  rewrite /serpent_iv -(hshift hs).
  apply (prefix_octet_contract_determines_encoding core.`cv_serpent_prefix record.`ev_serpent_iv shifted).
  + by smt().
  + by move: hc; rewrite /constructor_iv_post hpref; smt().
  by move: hc; rewrite /constructor_iv_post hpref; smt().
qed.

lemma constructor_success_determines_expectation core geometry index en me mc sz rs shifted record :
  core_domain core => geometry_domain geometry => uint64_domain index =>
  expectation_domain record =>
  (core.`cv_suite = 2 => shifted = go_u64_shift16 index) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  record = canonical_expectation core geometry index.
proof.
  move=> hd hg hi hr hshift hp.
  have hcl := constructor_success_count_index_length core geometry index en me mc sz rs shifted record hd hi hp.
  have hn := constructor_success_nonce core geometry index en me mc sz rs shifted record hd hr hp.
  have hiv := constructor_success_iv core geometry index en me mc sz rs shifted record hd hr hshift hp.
  have hs : constructor_scalar_post core geometry index record.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hdesc : descriptor_octet_contract record.`ev_descriptor index record.`ev_ciphertext_length record.`ev_final.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hb : 0 <= record.`ev_ciphertext_length < 4294967296 by move: hcl; rewrite /chunk_size; smt().
  have he := descriptor_octets_determine_encoding record.`ev_descriptor index record.`ev_ciphertext_length record.`ev_final hb hdesc.
  have hl : uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /uint64_domain /uint64_modulus; smt().
  have ho := offset_math_canonical core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs index hl _ _; first 2 by smt().
  rewrite /canonical_expectation /descriptor_offset /body_offset /descriptor_offset.
  clear hb hdesc hr hp.
  move: hs; rewrite /constructor_scalar_post /chunk_size.
  case: record he hn hiv hcl=> a b c d e f g h j k /=.
  by smt().
qed.

lemma constructor_success_core_geometry core geometry index en me mc sz rs shifted record :
  core_domain core => geometry_domain geometry =>
  policy_interpretation core me mc sz =>
  (rs <=> and1word core.`cv_features <> UInt16.zerow) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  concrete_core_policy core /\
  geometry_guard_view core geometry.`gv_front_header_length geometry.`gv_payload_length
    geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs.
proof.
  move=> hd hg hi hrs hp.
  have hmagic : me by move: hp; rewrite /constructor_success_post; smt().
  have hn : constructor_numeric_input core geometry index mc sz rs.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hs := constructor_numeric_implies_source_guard core geometry index mc sz rs hd hg hn.
  have hinterp : policy_interpretation core true mc sz by smt().
  have he := rgm_source_policy_represents_geometry core geometry true mc sz rs hd hg hinterp hrs.
  by smt().
qed.

op expectation_slot commitment (record : expectation_view) : slot =
  (commitment, take 8 record.`ev_descriptor, drop 8 record.`ev_descriptor, record.`ev_ciphertext_length).

lemma canonical_expectation_slot core geometry index commitment :
  expectation_slot commitment (canonical_expectation core geometry index) =
  canonical_slot commitment core.`cv_plaintext_length index.
proof.
  rewrite /expectation_slot /canonical_expectation /= take_size_cat; first by rewrite size_be64.
  rewrite drop_size_cat; first by rewrite size_be64.
  by rewrite /canonical_slot /record_body_length.
qed.

lemma constructor_success_profile_slot core geometry index en me mc sz rs shifted record commitment :
  core_domain core => geometry_domain geometry => uint64_domain index =>
  expectation_domain record =>
  (core.`cv_suite = 2 => shifted = go_u64_shift16 index) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  expectation_slot commitment record =
    nth witness (canonical_profile commitment core.`cv_plaintext_length) index.
proof.
  move=> hd hg hi hr hshift hp.
  have he := constructor_success_determines_expectation core geometry index en me mc sz rs shifted record hd hg hi hr hshift hp.
  have hc := constructor_success_count_index_length core geometry index en me mc sz rs shifted record hd hi hp.
  have hl : uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /uint64_domain /uint64_modulus; smt().
  by rewrite he canonical_expectation_slot (canonical_profile_slot commitment core.`cv_plaintext_length index hl _) 1:/#.
qed.

lemma constructor_success_intrinsic_extents core geometry index en me mc sz rs shifted record :
  core_domain core => geometry_domain geometry => uint64_domain index =>
  policy_interpretation core me mc sz =>
  (rs <=> and1word core.`cv_features <> UInt16.zerow) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  0 <= descriptor_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= max_int64 /\
  0 <= body_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= max_int64 /\
  record_end geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= geometry.`gv_backup_capsule_offset /\
  (index = geometry.`gv_record_count =>
    record_end geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index = geometry.`gv_backup_capsule_offset).
proof.
  move=> hd hg hi hinterp hrs hp.
  have hcg := constructor_success_core_geometry core geometry index en me mc sz rs shifted record hd hg hinterp hrs hp.
  have hn : constructor_numeric_input core geometry index mc sz rs.
  + by move: hp; rewrite /constructor_success_post; smt().
  have hindex : 0 <= index <= geometry.`gv_record_count.
  + by move: hn hi; rewrite /constructor_numeric_input /uint64_domain; smt().
  have hvalid : concrete_core_policy core by smt().
  have hguard : geometry_guard_view core geometry.`gv_front_header_length geometry.`gv_payload_length
    geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs by smt().
  exact (core_and_geometry_record_extents core geometry.`gv_front_header_length geometry.`gv_payload_length
    geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs index hd hvalid hguard hindex).
qed.

lemma constructor_success_unique core geometry index en me mc sz rs shifted record1 record2 :
  core_domain core => geometry_domain geometry => uint64_domain index =>
  expectation_domain record1 => expectation_domain record2 =>
  (core.`cv_suite = 2 => shifted = go_u64_shift16 index) =>
  constructor_success_post core geometry index en me mc sz rs shifted record1 =>
  constructor_success_post core geometry index en me mc sz rs shifted record2 =>
  record1 = record2.
proof.
  move=> hd hg hi hf hs hshift hp hq.
  have hfirst := constructor_success_determines_expectation core geometry index en me mc sz rs shifted record1 hd hg hi hf hshift hp.
  have hsecond := constructor_success_determines_expectation core geometry index en me mc sz rs shifted record2 hd hg hi hs hshift hq.
  by smt().
qed.

lemma constructor_success_valid_profile_slot core geometry index en me mc sz rs shifted record commitment :
  core_domain core => geometry_domain geometry => uint64_domain index =>
  expectation_domain record => size commitment = 32 =>
  (core.`cv_suite = 2 => shifted = go_u64_shift16 index) =>
  constructor_success_post core geometry index en me mc sz rs shifted record =>
  valid_profile (canonical_profile commitment core.`cv_plaintext_length) /\
  expectation_slot commitment record = nth witness (canonical_profile commitment core.`cv_plaintext_length) index.
proof.
  move=> hd hg hi hr hcommit hshift hp.
  have hl : uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /uint64_domain /uint64_modulus; smt().
  have hv := canonical_profile_valid commitment core.`cv_plaintext_length hcommit hl.
  have hs := constructor_success_profile_slot core geometry index en me mc sz rs shifted record commitment hd hg hi hr hshift hp.
  by split.
qed.

lemma constructor_success_nonvacuous :
  exists core geometry record,
    core_domain core /\ geometry_domain geometry /\ expectation_domain record /\
    policy_interpretation core true true true /\
    (false <=> and1word core.`cv_features <> UInt16.zerow) /\
    record = canonical_expectation core geometry 0 /\
    constructor_success_post core geometry 0 true true true true false 0 record.
proof.
  pose core := policy_fixture 3 0 normal_magic.
  pose geometry := geometry_fixture 0 777 (-17) (-99).
  pose record := canonical_expectation core geometry 0.
  have hcore : core_domain core by have h := policy_nonvacuous; smt().
  have hgeom : geometry_domain geometry.
  + by rewrite /geometry /geometry_domain /geometry_fixture
      /uint64_domain /int64_domain /min_int64 /max_int64 /uint64_modulus.
  have hrecord : expectation_domain record.
  + by rewrite /record /expectation_domain /canonical_expectation /core /geometry
      /policy_fixture /geometry_fixture /record_nonce /descriptor_offset /body_offset
      /record_offset /data_prefix /record_body_length /canonical_count /chunk_size
      /encoded_body_length /semantic_body_length /ceiling /= /uint64_domain
      /int64_domain /min_int64 /max_int64 /uint64_modulus;
      smt(size_cat size_be64 size_be32 size_descriptor_tail size_nseq).
  have hmask := clear3_zero_iff 0 _; first by done.
  have hrs := and1_nonzero_iff_odd 0 _; first by done.
  have hinterp : policy_interpretation core true true true.
  + by rewrite /policy_interpretation /core /policy_fixture /=; smt().
  have hdesc : descriptor_octet_contract (be64 0 ++ descriptor_tail 0 true) 0 0 true.
  + rewrite /descriptor_octet_contract.
    split; first by rewrite size_cat size_be64 size_descriptor_tail.
    split.
    - move=> j hj.
      have hj8 : j < 8 by smt().
      rewrite nth_cat size_be64 hj8 /=.
      exact (be64_octet 0 j hj).
    split.
    - move=> j hj.
      have hj8 : !(8+j < 8) by smt().
      have hj4 : j < 4 by smt().
      have hzero : 0 <= 0 < 4294967296 by done.
      rewrite nth_cat size_be64 hj8 /= /descriptor_tail nth_cat size_be32 hj4 /=.
      exact (be32_low_octet64 0 j hzero hj).
    by rewrite /descriptor_tail !nth_cat !size_be64 !size_be32 /=.
  have hnonce : constructor_nonce_post core 0 record.
  + rewrite /constructor_nonce_post /record /canonical_expectation /record_nonce
      /core /policy_fixture /=.
    split.
    - move=> j hj.
      have hj16 : j < 16 by smt().
      by rewrite nth_cat size_nseq /= hj16.
    move=> j hj.
    have hj16 : !(16+j < 16) by smt().
    rewrite nth_cat size_nseq /= hj16 /=.
    exact (be64_octet 0 j hj).
  have hpost : constructor_success_post core geometry 0 true true true true false 0 record.
  + rewrite /constructor_success_post.
    have hnum : constructor_numeric_input core geometry 0 true true false.
    - by rewrite /constructor_numeric_input /source_core_policy /core /geometry
        /policy_fixture /geometry_fixture /rgm_payload_total.
    have hscalar : constructor_scalar_post core geometry 0 record.
    - by rewrite /constructor_scalar_post /record /canonical_expectation /core /geometry
        /policy_fixture /geometry_fixture /constructor_length_source /offset_math
        /descriptor_offset /body_offset /record_offset /data_prefix /record_body_length
        /canonical_count /chunk_size /encoded_body_length /semantic_body_length /ceiling.
    have hd : descriptor_octet_contract record.`ev_descriptor 0 record.`ev_ciphertext_length record.`ev_final.
    - by move: hdesc; rewrite /record /canonical_expectation /core /policy_fixture
        /record_body_length /canonical_count /=.
    have hiv : constructor_iv_post core 0 record.
    - by rewrite /constructor_iv_post /record /canonical_expectation /core /policy_fixture.
    by smt().
  exists core geometry record.
  by move: hrs; rewrite /core /policy_fixture /=; smt().
qed.
