require import AllCore IntDiv List BitEncoding.
require import RecordFraming BigEndianFields CanonicalRecords PayloadGeometry.
import BS2Int.
clone BitWord as UInt16 with op n <- 16 proof gt0_n by done.
import UInt16.

op u16word (value : int) : UInt16.word = UInt16.mkword (int2bs 16 value).
op u16value (word : UInt16.word) : int = bs2int (UInt16.ofword word).
op clear3word (value : int) : UInt16.word =
  UInt16.andw (u16word value) (UInt16.invw (u16word 3)).
op and1word (value : int) : UInt16.word = UInt16.andw (u16word value) (u16word 1).
op cleared_bits (value : int) : bool list = nseq 2 false ++ drop 2 (int2bs 16 value).

lemma u16word_bits value : UInt16.ofword (u16word value) = int2bs 16 value.
proof. by rewrite /u16word UInt16.ofwordK // size_int2bs. qed.

lemma word3_bits : int2bs 16 3 = [true; true] ++ nseq 14 false.
proof. by rewrite (int2bs_cons 16 3) // (int2bs_cons 15 1) // int2bs0. qed.

lemma word1_bits : int2bs 16 1 = [true] ++ nseq 15 false.
proof. by rewrite int2bs_cons // int2bs0. qed.

lemma clear3_bits value : UInt16.ofword (clear3word value) = cleared_bits value.
proof.
  apply (eq_from_nth false).
  + rewrite UInt16.size_word /cleared_bits size_cat size_nseq size_drop // size_int2bs; smt().
  move=> k hk.
  have krange : 0 <= k < 16 by move: hk; rewrite UInt16.size_word.
  have hmask : (u16word 3).[k] = (k < 2).
  + rewrite UInt16.getE krange u16word_bits word3_bits nth_cat /=.
    case: (k < 2); first by smt().
    move=> h; rewrite nth_nseq //; smt().
  have hget : nth false (UInt16.ofword (clear3word value)) k =
    (clear3word value).[k] by rewrite UInt16.getE krange; smt(nth_change_dfl UInt16.size_word).
  rewrite hget /clear3word UInt16.andwE UInt16.invwE // hmask.
  rewrite /cleared_bits nth_cat size_nseq /=.
  case: (k < 2); first by smt(nth_nseq).
  move=> h; rewrite nth_drop 1,2:/#.
  have -> : 2 + (k - 2) = k by ring.
  by rewrite UInt16.getE krange u16word_bits; smt(nth_change_dfl size_int2bs).
qed.

lemma clear3_numeric value :
  0 <= value < 65536 => u16value (clear3word value) = 4 * (value %/ 4).
proof.
  move=> hv.
  rewrite /u16value clear3_bits /cleared_bits bs2int_cat size_nseq /= bs2int_nseq_false /=.
  have h := bs2int_div 2 (int2bs 16 value) _; first by done.
  have hp : 2^16 = 65536 by ring.
  have hvbits : 0 <= value < 2^16 by rewrite hp.
  have hvalue := int2bsK 16 value _ hvbits; first by done.
  have htwo : 2^2 = 4 by ring.
  have hmax : max 0 2 = 2 by smt().
  by move: h; rewrite hvalue htwo; move=> h; rewrite hmax htwo; smt().
qed.

lemma clear3_zero_iff value :
  0 <= value < 65536 => (clear3word value = UInt16.zerow <=> value <= 3).
proof.
  move=> hv.
  have h := clear3_numeric value hv.
  have hz := UInt16.zerow_int.
  have hinj : forall x y, u16value x = u16value y => x = y.
  + move=> x y he; apply UInt16.ofword_inj.
    apply inj_bs2int_eqsize; first by rewrite !UInt16.size_word.
    exact he.
  have hdiv := divz_eq value 4.
  have hmod := modz_ge0 value 4 _; first by done.
  have hmodhi := ltz_pmod value 4 _; first by done.
  have hq := divz_ge0 value 4 _; first by done.
  smt().
qed.

lemma and1_bits value : UInt16.ofword (and1word value) =
  [nth false (int2bs 16 value) 0] ++ nseq 15 false.
proof.
  apply (eq_from_nth false).
  + by rewrite UInt16.size_word size_cat size_nseq.
  move=> k hk.
  have krange : 0 <= k < 16 by move: hk; rewrite UInt16.size_word.
  have hmask : (u16word 1).[k] = (k = 0).
  + rewrite UInt16.getE krange u16word_bits word1_bits nth_cat /=.
    case: (k < 1); first by smt().
    move=> h; rewrite nth_nseq //; smt().
  have hget : nth false (UInt16.ofword (and1word value)) k =
    (and1word value).[k] by rewrite UInt16.getE krange; smt(nth_change_dfl UInt16.size_word).
  rewrite hget /and1word UInt16.andwE hmask nth_cat /=.
  case: (k = 0)=> [->|hk0].
  + by rewrite UInt16.getE u16word_bits /=; smt(nth_change_dfl size_int2bs).
  by rewrite nth_nseq //; smt().
qed.

lemma and1_numeric value :
  0 <= value < 65536 => u16value (and1word value) = value %% 2.
proof.
  move=> hv.
  rewrite /u16value and1_bits bs2int_cat /= bs2int_nseq_false /=.
  have htake : take 1 (int2bs 16 value) = [nth false (int2bs 16 value) 0].
  + by rewrite (int2bs_cons 16 value) //= take0.
  have h := bs2int_mod (int2bs 16 value) 1 _; first by done.
  have hp : 2^16 = 65536 by ring.
  have hvbits : 0 <= value < 2^16 by rewrite hp.
  have hvalue := int2bsK 16 value _ hvbits; first by done.
  have htwo : 2^1 = 2 by ring.
  by move: h; rewrite hvalue htake htwo; smt(bs2int_cons bs2int_nil).
qed.

lemma and1_nonzero_iff_odd value :
  0 <= value < 65536 =>
  (and1word value <> UInt16.zerow <=> value %% 2 = 1).
proof.
  move=> hv.
  have h := and1_numeric value hv.
  have hz := UInt16.zerow_int.
  have hinj : forall x y, u16value x = u16value y => x = y.
  + move=> x y he; apply UInt16.ofword_inj.
    apply inj_bs2int_eqsize; first by rewrite !UInt16.size_word.
    exact he.
  have hlo := modz_ge0 value 2 _; first by done.
  have hhi := ltz_pmod value 2 _; first by done.
  smt().
qed.

(* This view retains every core field. The Go-to-view mapping and observations
   are premises; these mathematical definitions are not a Go implementation. *)
type core_view = {
  cv_magic : bytes;
  cv_major : int;
  cv_schema : int;
  cv_suite : int;
  cv_features : int;
  cv_front_header : int;
  cv_volume_id : bytes;
  cv_payload_kind : int;
  cv_record_profile : int;
  cv_metadata_profile : int;
  cv_reserved : int;
  cv_plaintext_length : int;
  cv_record_count : int;
  cv_xnonce_prefix : bytes;
  cv_serpent_prefix : bytes;
  cv_comment_length : int
}.

op normal_magic : bytes = List.map byte_of_int [80; 67; 86; 0].
op zero_serpent : bytes = nseq 8 (byte_of_int 0).
op core_domain (core : core_view) : bool =
  size core.`cv_magic = 4 /\ size core.`cv_volume_id = 32 /\
  size core.`cv_xnonce_prefix = 16 /\ size core.`cv_serpent_prefix = 8 /\
  0 <= core.`cv_major < 65536 /\ 0 <= core.`cv_schema < 65536 /\
  0 <= core.`cv_suite < 65536 /\ 0 <= core.`cv_features < 65536 /\
  0 <= core.`cv_front_header < 4294967296 /\
  0 <= core.`cv_payload_kind < 256 /\ 0 <= core.`cv_record_profile < 256 /\
  0 <= core.`cv_metadata_profile < 256 /\ 0 <= core.`cv_reserved < 256 /\
  0 <= core.`cv_plaintext_length < 18446744073709551616 /\
  0 <= core.`cv_record_count < 18446744073709551616 /\
  0 <= core.`cv_comment_length < 4294967296.

op concrete_core_policy (core : core_view) : bool =
  core.`cv_magic = normal_magic /\ core.`cv_major = 3 /\ core.`cv_schema = 1 /\
  (core.`cv_suite = 1 \/ core.`cv_suite = 2) /\ 0 <= core.`cv_features <= 3 /\
  1 <= core.`cv_payload_kind <= 2 /\ core.`cv_record_profile = 1 /\
  core.`cv_metadata_profile = 1 /\ core.`cv_reserved = 0 /\
  core.`cv_comment_length <= 99999 /\
  core.`cv_record_count = canonical_count core.`cv_plaintext_length /\
  core.`cv_record_count < 281474976710656 /\
  (core.`cv_suite <> 1 \/ core.`cv_serpent_prefix = zero_serpent) /\
  core.`cv_front_header = header_length core.`cv_comment_length.

(* The first and third Booleans observe raw Go string/array comparisons.
   The second observes Go's UInt16 AND-NOT; their meanings stay explicit. *)
op source_core_policy (core : core_view) (magic_equal mask_clear serpent_zero : bool) : bool =
  magic_equal /\ core.`cv_major = 3 /\ core.`cv_schema = 1 /\
  (core.`cv_suite = 1 \/ core.`cv_suite = 2) /\ mask_clear /\
  1 <= core.`cv_payload_kind <= 2 /\ core.`cv_record_profile = 1 /\
  core.`cv_metadata_profile = 1 /\ core.`cv_reserved = 0 /\
  core.`cv_comment_length <= 99999 /\
  core.`cv_record_count = core.`cv_plaintext_length %/ 1048576 +
    (if core.`cv_plaintext_length %% 1048576 = 0 then 0 else 1) /\
  core.`cv_record_count < 281474976710656 /\
  (core.`cv_suite <> 1 \/ serpent_zero) /\
  core.`cv_front_header = 976 + 136 *
    ((80 + core.`cv_comment_length) %/ 128 +
      if (80 + core.`cv_comment_length) %% 128 = 0 then 0 else 1).

op policy_interpretation (core : core_view) (magic_equal mask_clear serpent_zero : bool) : bool =
  (magic_equal <=> core.`cv_magic = normal_magic) /\
  (mask_clear <=> clear3word core.`cv_features = UInt16.zerow) /\
  (serpent_zero <=> core.`cv_serpent_prefix = zero_serpent).

lemma normal_magic_exact : size normal_magic = 4 /\
  from_be normal_magic = 1346590208 /\
  nth (byte_of_int 1) normal_magic 3 = byte_of_int 0.
proof.
  rewrite /normal_magic /=.
  have h1 := from_be_cat [byte_of_int 80] [byte_of_int 67; byte_of_int 86; byte_of_int 0].
  have h2 := from_be_cat [byte_of_int 67] [byte_of_int 86; byte_of_int 0].
  have h3 := from_be_cat [byte_of_int 86] [byte_of_int 0].
  have hn := from_be_byte 0 _; first by done.
  have h80 := from_be_byte 80 _; first by done.
  have h67 := from_be_byte 67 _; first by done.
  have h86 := from_be_byte 86 _; first by done.
  have hp1 : 2^8=256 by ring.
  have hp2 : 2^16=65536 by ring.
  have hp3 : 2^24=16777216 by ring.
  by move: h1 h2 h3; rewrite /= h80 h67 h86 hn hp1 hp2 hp3; smt().
qed.

lemma source_policy_represents_concrete core magic_equal mask_clear serpent_zero accepted :
  core_domain core => policy_interpretation core magic_equal mask_clear serpent_zero =>
  accepted = source_core_policy core magic_equal mask_clear serpent_zero =>
  (accepted <=> concrete_core_policy core).
proof.
  rewrite /core_domain /policy_interpretation /source_core_policy /concrete_core_policy.
  move=> hdomain hinterp ->.
  have hmask := clear3_zero_iff core.`cv_features _; first by smt().
  have hcount := canonical_count_quotient core.`cv_plaintext_length _.
  + by rewrite /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  rewrite hcount /chunk_size /header_length /metadata_blocks /ceiling.
  smt().
qed.

lemma concrete_policy_canonical_geometry core :
  core_domain core => concrete_core_policy core =>
  core.`cv_record_count = canonical_count core.`cv_plaintext_length /\
  core.`cv_record_count <= 17592186044416 /\
  core.`cv_front_header = header_length core.`cv_comment_length /\
  1112 <= core.`cv_front_header <= 107328 /\
  1 <= metadata_blocks core.`cv_comment_length <= 782.
proof.
  move=> hd hp.
  have hcount := canonical_count_bound core.`cv_plaintext_length _.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  have hmetadata := metadata_header_bounds core.`cv_comment_length _.
  + by move: hd hp; rewrite /core_domain /concrete_core_policy; smt().
  by move: hp hcount hmetadata; rewrite /concrete_core_policy /reachable_count_bound; smt().
qed.

op policy_fixture (major features : int) (magic : bytes) : core_view = {|
  cv_magic = magic;
  cv_major = major;
  cv_schema = 1;
  cv_suite = 1;
  cv_features = features;
  cv_front_header = 1112;
  cv_volume_id = nseq 32 (byte_of_int 0);
  cv_payload_kind = 1;
  cv_record_profile = 1;
  cv_metadata_profile = 1;
  cv_reserved = 0;
  cv_plaintext_length = 0;
  cv_record_count = 0;
  cv_xnonce_prefix = nseq 16 (byte_of_int 0);
  cv_serpent_prefix = zero_serpent;
  cv_comment_length = 0
|}.

lemma policy_nonvacuous :
  core_domain (policy_fixture 3 0 normal_magic) /\
  concrete_core_policy (policy_fixture 3 0 normal_magic).
proof.
  rewrite /core_domain /concrete_core_policy /policy_fixture /normal_magic /zero_serpent
    /= /canonical_count /header_length /metadata_blocks /ceiling /= !size_nseq /=; smt().
qed.

lemma wrong_major_control :
  !concrete_core_policy (policy_fixture 2 0 normal_magic).
proof. by rewrite /concrete_core_policy /policy_fixture. qed.

lemma unknown_flag_control :
  clear3word 4 <> UInt16.zerow /\
  !concrete_core_policy (policy_fixture 3 4 normal_magic).
proof.
  have h := clear3_zero_iff 4 _; first by done.
  by rewrite /concrete_core_policy /policy_fixture; smt().
qed.

lemma wrong_magic_control :
  !concrete_core_policy (policy_fixture 3 0 (List.map byte_of_int [80; 67; 86; 1])).
proof.
  have hlast := byte_zero_one.
  rewrite /concrete_core_policy /policy_fixture /normal_magic /=.
  smt().
qed.

lemma source_rs_mode_represents_odd core rs_observed :
  core_domain core =>
  (rs_observed <=> and1word core.`cv_features <> UInt16.zerow) =>
  (rs_observed <=> core.`cv_features %% 2 = 1).
proof.
  rewrite /core_domain => hd hs.
  have h := and1_nonzero_iff_odd core.`cv_features _; first by smt().
  smt().
qed.

lemma accepted_feature_modes core rs_observed :
  concrete_core_policy core =>
  (rs_observed <=> core.`cv_features %% 2 = 1) =>
  (rs_observed <=> core.`cv_features = 1 \/ core.`cv_features = 3) /\
  (!rs_observed <=> core.`cv_features = 0 \/ core.`cv_features = 2).
proof.
  rewrite /concrete_core_policy => hp hr.
  have h := divz_eq core.`cv_features 2.
  have hlo := modz_ge0 core.`cv_features 2 _; first by done.
  have hhi := ltz_pmod core.`cv_features 2 _; first by done.
  smt().
qed.

lemma magic_interpretation_is_required :
  source_core_policy (policy_fixture 3 0 (List.map byte_of_int [80; 67; 86; 1])) true true true /\
  !concrete_core_policy (policy_fixture 3 0 (List.map byte_of_int [80; 67; 86; 1])).
proof.
  split; last exact wrong_magic_control.
  by rewrite /source_core_policy /policy_fixture.
qed.

lemma mask_interpretation_is_required :
  source_core_policy (policy_fixture 3 4 normal_magic) true true true /\
  !concrete_core_policy (policy_fixture 3 4 normal_magic).
proof.
  have h := unknown_flag_control.
  by rewrite /source_core_policy /policy_fixture; smt().
qed.

(* These explicit equalities are the handoff obligation for a later source
   proof of recordGeometryMatchesCore, including its intrinsic H+P bound. *)
op geometry_guard_view (core : core_view) (header payload backup count : int) (rs : bool) : bool =
  count = core.`cv_record_count /\
  (rs <=> core.`cv_features %% 2 = 1) /\
  header = core.`cv_front_header /\ payload = payload_length core.`cv_plaintext_length rs /\
  backup = header + payload /\ 0 <= backup <= SafeCastRepresentation.max_int64.

lemma core_and_geometry_record_extents core header payload backup count rs index :
  core_domain core => concrete_core_policy core =>
  geometry_guard_view core header payload backup count rs =>
  0 <= index <= count =>
  0 <= descriptor_offset header core.`cv_plaintext_length rs index <= SafeCastRepresentation.max_int64 /\
  0 <= body_offset header core.`cv_plaintext_length rs index <= SafeCastRepresentation.max_int64 /\
  record_end header core.`cv_plaintext_length rs index <= backup /\
  (index = count => record_end header core.`cv_plaintext_length rs index = backup).
proof.
  move=> hd hp hg hi.
  have hl : SafeCastRepresentation.uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  have hmeta := concrete_policy_canonical_geometry core hd hp.
  have hc : count = canonical_count core.`cv_plaintext_length.
  + by move: hg hp; rewrite /geometry_guard_view /concrete_core_policy; smt().
  have hindex : 0 <= index <= canonical_count core.`cv_plaintext_length by smt().
  have hh : 0 <= header.
  + by move: hmeta hg; rewrite /geometry_guard_view; smt().
  have hfit : header + payload_length core.`cv_plaintext_length rs <= SafeCastRepresentation.max_int64.
  + by move: hg; rewrite /geometry_guard_view; smt().
  have he := record_host_extents header core.`cv_plaintext_length rs index hl hindex hh hfit.
  by move: he hg; rewrite /geometry_guard_view; smt().
qed.

(* All eight source Geometry fields remain in the typed view. The last three
   unread values are not metadata, trailer, suffix or EOF validation claims. *)
type geometry_view = {
  gv_metadata_blocks : int;
  gv_payload_body_rs : bool;
  gv_record_count : int;
  gv_front_header_length : int;
  gv_payload_length : int;
  gv_backup_capsule_offset : int;
  gv_trailer_offset : int;
  gv_file_size : int
}.

op geometry_domain (geometry : geometry_view) : bool =
  SafeCastRepresentation.uint64_domain geometry.`gv_metadata_blocks /\
  SafeCastRepresentation.uint64_domain geometry.`gv_record_count /\
  SafeCastRepresentation.int64_domain geometry.`gv_front_header_length /\
  SafeCastRepresentation.int64_domain geometry.`gv_payload_length /\
  SafeCastRepresentation.int64_domain geometry.`gv_backup_capsule_offset /\
  SafeCastRepresentation.int64_domain geometry.`gv_trailer_offset /\
  SafeCastRepresentation.int64_domain geometry.`gv_file_size.

(* These are the expanded mathematical-integer PayloadValid/Total ghost bodies
   in the source postcondition; their equality to prior geometry is proved. *)
op rgm_payload_valid (length count : int) : bool =
  count = length %/ 1048576 + (if length %% 1048576 = 0 then 0 else 1) /\
  count < 281474976710656.
op rgm_payload_total (length : int) (rs : bool) : int =
  (if rs then (length %/ 1048576) * 1114296 +
    (if length %% 1048576 = 0 then 0 else
      48 + 136 * (((length %% 1048576) + 64) %/ 128 +
        (if ((length %% 1048576) + 64) %% 128 = 0 then 0 else 1)))
   else length + (length %/ 1048576 +
     (if length %% 1048576 = 0 then 0 else 1)) * 112) +
  (if rs then 184 else 112).

lemma rgm_payload_valid_representation length count :
  SafeCastRepresentation.uint64_domain length =>
  rgm_payload_valid length count = payload_valid_count length count.
proof.
  move=> hl.
  by rewrite (payload_valid_ghost_formula length count hl)
    /rgm_payload_valid /chunk_size /maximum_record_count.
qed.

lemma rgm_payload_total_representation length rs :
  SafeCastRepresentation.uint64_domain length =>
  rgm_payload_total length rs = payload_length length rs.
proof.
  move=> hl.
  by rewrite (payload_total_ghost_formula length rs hl)
    encoded_body_ghost_formula /rgm_payload_total /chunk_size.
qed.

op rgm_source_policy (core : core_view) (geometry : geometry_view)
    (magic_equal mask_clear serpent_zero rs_bit : bool) : bool =
  source_core_policy core magic_equal mask_clear serpent_zero /\
  0 <= geometry.`gv_front_header_length /\ 0 <= geometry.`gv_payload_length /\
  0 <= geometry.`gv_backup_capsule_offset /\
  geometry.`gv_record_count = core.`cv_record_count /\
  geometry.`gv_payload_body_rs = rs_bit /\
  geometry.`gv_front_header_length = core.`cv_front_header /\
  rgm_payload_valid core.`cv_plaintext_length core.`cv_record_count /\
  rgm_payload_total core.`cv_plaintext_length geometry.`gv_payload_body_rs < SafeCastRepresentation.uint64_modulus /\
  geometry.`gv_payload_length = rgm_payload_total core.`cv_plaintext_length geometry.`gv_payload_body_rs /\
  geometry.`gv_front_header_length + rgm_payload_total core.`cv_plaintext_length geometry.`gv_payload_body_rs < SafeCastRepresentation.uint64_modulus /\
  geometry.`gv_backup_capsule_offset = geometry.`gv_front_header_length +
    rgm_payload_total core.`cv_plaintext_length geometry.`gv_payload_body_rs.

op rgm_source_contract (core : core_view) (geometry : geometry_view)
    (magic_equal mask_clear serpent_zero rs_bit matches : bool) : bool =
  matches = rgm_source_policy core geometry magic_equal mask_clear serpent_zero rs_bit.

(* This is a word-level execution reference using prior checked-helper models,
   not another assumed application helper or an automatic source translation. *)
op rgm_word_execution (core : core_view) (geometry : geometry_view)
    (magic_equal mask_clear serpent_zero rs_bit : bool) : bool =
  if !source_core_policy core magic_equal mask_clear serpent_zero \/
      geometry.`gv_front_header_length < 0 \/ geometry.`gv_payload_length < 0 \/
      geometry.`gv_backup_capsule_offset < 0 \/
      geometry.`gv_record_count <> core.`cv_record_count \/
      geometry.`gv_payload_body_rs <> rs_bit \/
      SafeCastRepresentation.unsigned_cast geometry.`gv_front_header_length <>
        SafeCastRepresentation.unsigned_cast core.`cv_front_header then false
  else let payload = payload_execution core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs in
    if !payload.`2 \/ SafeCastRepresentation.unsigned_cast geometry.`gv_payload_length <> payload.`1 then false
    else let backup = WordArithmetic.checked_add
        (SafeCastRepresentation.unsigned_cast geometry.`gv_front_header_length) payload.`1 in
      backup.`2 /\ SafeCastRepresentation.unsigned_cast geometry.`gv_backup_capsule_offset = backup.`1.

lemma payload_success_at_signed_view length count rs value :
  SafeCastRepresentation.uint64_domain length =>
  SafeCastRepresentation.uint64_domain count =>
  SafeCastRepresentation.int64_domain value => 0 <= value =>
  ((payload_execution length count rs).`2 /\
    SafeCastRepresentation.unsigned_cast value = (payload_execution length count rs).`1) =
  (payload_valid_count length count /\
    payload_length length rs < SafeCastRepresentation.uint64_modulus /\
    value = payload_length length rs).
proof.
  move=> hl hc hv hn.
  have hs := payload_execution_source_contract length count rs hl hc.
  have hf := payload_source_contract_fields length count rs
    (payload_execution length count rs).`1 (payload_execution length count rs).`2.
  have hcast := SafeCastRepresentation.unsigned_cast_nonnegative_int64 value hv hn.
  case: (payload_execution length count rs).`2 => hok.
  + have he := payload_source_contract_success length count rs
      (payload_execution length count rs).`1 (payload_execution length count rs).`2 hl hc hs hok.
    smt().
  smt().
qed.

lemma add_success_at_signed_view left_value right_value value :
  SafeCastRepresentation.int64_domain left_value => 0 <= left_value =>
  SafeCastRepresentation.uint64_domain right_value =>
  SafeCastRepresentation.int64_domain value => 0 <= value =>
  ((WordArithmetic.checked_add (SafeCastRepresentation.unsigned_cast left_value) right_value).`2 /\
    SafeCastRepresentation.unsigned_cast value =
      (WordArithmetic.checked_add (SafeCastRepresentation.unsigned_cast left_value) right_value).`1) =
  (left_value + right_value < SafeCastRepresentation.uint64_modulus /\ value = left_value + right_value).
proof.
  move=> hl hn hr hv hvn.
  have hc := SafeCastRepresentation.unsigned_cast_nonnegative_int64 left_value hl hn.
  have hvc := SafeCastRepresentation.unsigned_cast_nonnegative_int64 value hv hvn.
  have hleft : SafeCastRepresentation.uint64_domain left_value.
  + by move: hl hn; rewrite /SafeCastRepresentation.int64_domain
      /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.min_int64
      /SafeCastRepresentation.max_int64 /SafeCastRepresentation.uint64_modulus; smt().
  have hf := WordArithmetic.checked_add_flag left_value right_value hleft hr.
  rewrite hc hvc.
  case: (WordArithmetic.checked_add left_value right_value).`2 => hok.
  + have he := WordArithmetic.checked_add_success left_value right_value hleft hr hok.
    smt().
  smt().
qed.

lemma rgm_word_execution_closed_form core geometry magic_equal mask_clear serpent_zero rs_bit :
  core_domain core => geometry_domain geometry =>
  rgm_word_execution core geometry magic_equal mask_clear serpent_zero rs_bit =
    rgm_source_policy core geometry magic_equal mask_clear serpent_zero rs_bit.
proof.
  move=> hd hg.
  have hl : SafeCastRepresentation.uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  have hc : SafeCastRepresentation.uint64_domain core.`cv_record_count.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  have hheader : SafeCastRepresentation.int64_domain core.`cv_front_header.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.int64_domain
      /SafeCastRepresentation.min_int64 /SafeCastRepresentation.max_int64; smt().
  have hcorecast := SafeCastRepresentation.unsigned_cast_nonnegative_int64 core.`cv_front_header hheader _.
  + by move: hd; rewrite /core_domain; smt().
  have htotal := rgm_payload_total_representation core.`cv_plaintext_length geometry.`gv_payload_body_rs hl.
  have hvalid := rgm_payload_valid_representation core.`cv_plaintext_length core.`cv_record_count hl.
  rewrite /rgm_word_execution /rgm_source_policy htotal hvalid hcorecast.
  case: (0 <= geometry.`gv_front_header_length /\ 0 <= geometry.`gv_payload_length /\
      0 <= geometry.`gv_backup_capsule_offset) => hnonnegative; last by smt().
  have hgh : SafeCastRepresentation.int64_domain geometry.`gv_front_header_length
    by move: hg; rewrite /geometry_domain; smt().
  have hgp : SafeCastRepresentation.int64_domain geometry.`gv_payload_length
    by move: hg; rewrite /geometry_domain; smt().
  have hgb : SafeCastRepresentation.int64_domain geometry.`gv_backup_capsule_offset
    by move: hg; rewrite /geometry_domain; smt().
  have hcast := SafeCastRepresentation.unsigned_cast_nonnegative_int64 geometry.`gv_front_header_length hgh _; first by smt().
  rewrite hcast.
  have hp := payload_success_at_signed_view core.`cv_plaintext_length core.`cv_record_count
    geometry.`gv_payload_body_rs geometry.`gv_payload_length hl hc hgp _; first by smt().
  have hword := payload_result_range core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs.
  have hexec := payload_execution_closed_form core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs hl hc.
  have hpr : SafeCastRepresentation.uint64_domain
      (payload_execution core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs).`1 by smt().
  have ha := add_success_at_signed_view geometry.`gv_front_header_length
    (payload_execution core.`cv_plaintext_length core.`cv_record_count geometry.`gv_payload_body_rs).`1
    geometry.`gv_backup_capsule_offset hgh _ hpr hgb _; first 2 by smt().
  by smt().
qed.

lemma rgm_source_policy_represents_geometry core geometry magic_equal mask_clear serpent_zero rs_bit :
  core_domain core => geometry_domain geometry =>
  policy_interpretation core magic_equal mask_clear serpent_zero =>
  (rs_bit <=> and1word core.`cv_features <> UInt16.zerow) =>
  rgm_source_policy core geometry magic_equal mask_clear serpent_zero rs_bit =
    (concrete_core_policy core /\
      geometry_guard_view core geometry.`gv_front_header_length geometry.`gv_payload_length
        geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs).
proof.
  move=> hd hg hi hrs.
  have hcore := source_policy_represents_concrete core magic_equal mask_clear serpent_zero
    (source_core_policy core magic_equal mask_clear serpent_zero) hd hi _; first by done.
  have hrsbit := source_rs_mode_represents_odd core rs_bit hd hrs.
  have hl : SafeCastRepresentation.uint64_domain core.`cv_plaintext_length.
  + by move: hd; rewrite /core_domain /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus; smt().
  have ht := rgm_payload_total_representation core.`cv_plaintext_length geometry.`gv_payload_body_rs hl.
  have hv := rgm_payload_valid_representation core.`cv_plaintext_length core.`cv_record_count hl.
  have hpositive := payload_length_positive core.`cv_plaintext_length geometry.`gv_payload_body_rs hl.
  rewrite /rgm_source_policy hcore ht hv /geometry_guard_view.
  move: hd hg.
  rewrite /core_domain /geometry_domain /SafeCastRepresentation.int64_domain
    /SafeCastRepresentation.min_int64 /SafeCastRepresentation.max_int64
    /SafeCastRepresentation.uint64_modulus /payload_valid_count /concrete_core_policy.
  smt().
qed.

lemma rgm_source_contract_refines_geometry core geometry magic_equal mask_clear serpent_zero rs_bit matches :
  core_domain core => geometry_domain geometry =>
  policy_interpretation core magic_equal mask_clear serpent_zero =>
  (rs_bit <=> and1word core.`cv_features <> UInt16.zerow) =>
  rgm_source_contract core geometry magic_equal mask_clear serpent_zero rs_bit matches =>
  matches = (concrete_core_policy core /\
    geometry_guard_view core geometry.`gv_front_header_length geometry.`gv_payload_length
      geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs).
proof.
  move=> hd hg hi hrs.
  by rewrite /rgm_source_contract (rgm_source_policy_represents_geometry core geometry magic_equal mask_clear serpent_zero rs_bit hd hg hi hrs).
qed.

lemma rgm_source_contract_unique core geometry magic_equal mask_clear serpent_zero rs_bit matches1 matches2 :
  rgm_source_contract core geometry magic_equal mask_clear serpent_zero rs_bit matches1 =>
  rgm_source_contract core geometry magic_equal mask_clear serpent_zero rs_bit matches2 =>
  matches1 = matches2.
proof. by rewrite /rgm_source_contract; smt(). qed.

lemma rgm_source_contract_refines_execution core geometry magic_equal mask_clear serpent_zero rs_bit matches :
  core_domain core => geometry_domain geometry =>
  rgm_source_contract core geometry magic_equal mask_clear serpent_zero rs_bit matches =>
  matches = rgm_word_execution core geometry magic_equal mask_clear serpent_zero rs_bit.
proof.
  move=> hd hg.
  by rewrite /rgm_source_contract (rgm_word_execution_closed_form core geometry magic_equal mask_clear serpent_zero rs_bit hd hg).
qed.

lemma rgm_source_contract_record_extents core geometry magic_equal mask_clear serpent_zero rs_bit index :
  core_domain core => geometry_domain geometry =>
  policy_interpretation core magic_equal mask_clear serpent_zero =>
  (rs_bit <=> and1word core.`cv_features <> UInt16.zerow) =>
  rgm_source_contract core geometry magic_equal mask_clear serpent_zero rs_bit true =>
  0 <= index <= geometry.`gv_record_count =>
  0 <= descriptor_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= SafeCastRepresentation.max_int64 /\
  0 <= body_offset geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= SafeCastRepresentation.max_int64 /\
  record_end geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index <= geometry.`gv_backup_capsule_offset /\
  (index = geometry.`gv_record_count =>
    record_end geometry.`gv_front_header_length core.`cv_plaintext_length geometry.`gv_payload_body_rs index = geometry.`gv_backup_capsule_offset).
proof.
  move=> hd hg hi hrs hs hindex.
  have he := rgm_source_contract_refines_geometry core geometry magic_equal mask_clear serpent_zero rs_bit true hd hg hi hrs hs.
  have hp : concrete_core_policy core by smt().
  have hv : geometry_guard_view core geometry.`gv_front_header_length geometry.`gv_payload_length
      geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs by smt().
  exact (core_and_geometry_record_extents core geometry.`gv_front_header_length geometry.`gv_payload_length
    geometry.`gv_backup_capsule_offset geometry.`gv_record_count geometry.`gv_payload_body_rs index hd hp hv hindex).
qed.

op geometry_fixture (count metadata trailer size : int) : geometry_view = {|
  gv_metadata_blocks = metadata;
  gv_payload_body_rs = false;
  gv_record_count = count;
  gv_front_header_length = 1112;
  gv_payload_length = 112;
  gv_backup_capsule_offset = 1224;
  gv_trailer_offset = trailer;
  gv_file_size = size
|}.

lemma rgm_unread_fields_witness :
  geometry_domain (geometry_fixture 0 18446744073709551615 (-9223372036854775808) (-1)) /\
  rgm_source_policy (policy_fixture 3 0 normal_magic)
    (geometry_fixture 0 18446744073709551615 (-9223372036854775808) (-1)) true true true false.
proof.
  rewrite /geometry_domain /rgm_source_policy /source_core_policy /geometry_fixture
    /policy_fixture /rgm_payload_valid /rgm_payload_total
    /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.int64_domain
    /SafeCastRepresentation.min_int64 /SafeCastRepresentation.max_int64
    /SafeCastRepresentation.uint64_modulus /=; smt().
qed.

lemma rgm_count_mismatch_control :
  !rgm_source_policy (policy_fixture 3 0 normal_magic)
    (geometry_fixture 1 18446744073709551615 (-9223372036854775808) (-1)) true true true false.
proof. by rewrite /rgm_source_policy /policy_fixture /geometry_fixture. qed.
