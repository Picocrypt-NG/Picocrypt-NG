require import AllCore IntDiv.
require import SafeCastRepresentation CanonicalRecords WordArithmetic.
require import List RecordFraming BigEndianFields CanonicalProfile RecordDomains.

(* Mathematical extents from the public format constants. Correspondence with
   the Go geometry functions and standard-library arithmetic is separate. *)
op semantic_body_length (ciphertext : int) : int = ciphertext + 64.
op encoded_body_length (rs : bool) (ciphertext : int) : int =
  if rs then 136 * ceiling (semantic_body_length ciphertext) 128
  else semantic_body_length ciphertext.
op decoded_body_length (rs : bool) (ciphertext : int) : int =
  if rs then 128 * ceiling (semantic_body_length ciphertext) 128
  else semantic_body_length ciphertext.
op record_width (rs : bool) (ciphertext : int) : int =
  48 + encoded_body_length rs ciphertext.

op data_prefix (length : int) (rs : bool) : int =
  (length %/ chunk_size) * record_width rs chunk_size +
  (if length %% chunk_size = 0 then 0
   else record_width rs (length %% chunk_size)).
op payload_length (length : int) (rs : bool) : int =
  data_prefix length rs + record_width rs 0.
op record_body_length (length index : int) : int =
  if index = canonical_count length then 0 else chunk_length length index.
op record_offset (length : int) (rs : bool) (index : int) : int =
  if index < canonical_count length then index * record_width rs chunk_size
  else data_prefix length rs.

op metadata_blocks (comment : int) : int = ceiling (80 + comment) 128.
op header_length (comment : int) : int = 976 + 136 * metadata_blocks comment.
op backup_offset (length comment : int) (rs : bool) : int =
  header_length comment + payload_length length rs.
op trailer_offset (length comment : int) (rs : bool) : int =
  backup_offset length comment rs + 960.
op file_length (length comment : int) (rs : bool) : int =
  backup_offset length comment rs + 1008.

lemma ceiling_128_interval value :
  0 <= value =>
  0 <= ceiling value 128 /\
  value <= 128 * ceiling value 128 < value + 128.
proof.
  move=> hv.
  have he := divz_eq value 128.
  have hlo := modz_ge0 value 128 _; first by done.
  have hhi := ltz_pmod value 128 _; first by done.
  have hq := divz_ge0 value 128 _; first by done.
  by rewrite /ceiling; smt().
qed.

lemma encoded_body_bounds rs ciphertext :
  0 <= ciphertext <= chunk_size =>
  semantic_body_length ciphertext <= encoded_body_length rs ciphertext /\
  64 <= encoded_body_length rs ciphertext <= 1114248.
proof.
  move=> hc.
  have hk := ceiling_128_interval (semantic_body_length ciphertext) _.
  + by rewrite /semantic_body_length; move: hc; rewrite /chunk_size; smt().
  case: rs; rewrite /encoded_body_length /semantic_body_length /=;
    move: hk hc; rewrite /semantic_body_length /chunk_size; smt().
qed.

lemma decoded_body_bounds rs ciphertext :
  0 <= ciphertext <= chunk_size =>
  semantic_body_length ciphertext <= decoded_body_length rs ciphertext /\
  64 <= decoded_body_length rs ciphertext <= 1048704 /\
  0 <= decoded_body_length rs ciphertext - semantic_body_length ciphertext < 128.
proof.
  move=> hc.
  have hk := ceiling_128_interval (semantic_body_length ciphertext) _.
  + by rewrite /semantic_body_length; move: hc; rewrite /chunk_size; smt().
  case: rs; rewrite /decoded_body_length /semantic_body_length /=;
    move: hk hc; rewrite /semantic_body_length /chunk_size; smt().
qed.

lemma encoded_rs_body_alignment ciphertext :
  encoded_body_length true ciphertext %% 136 = 0.
proof. by rewrite /encoded_body_length /= modzMr. qed.

lemma decoded_rs_body_quotient ciphertext :
  encoded_body_length true ciphertext %/ 136 * 128 =
  decoded_body_length true ciphertext.
proof.
  rewrite /encoded_body_length /decoded_body_length /=.
  rewrite (mulrC 136 _) mulzK //.
  ring.
qed.

lemma full_record_width rs :
  record_width rs chunk_size = if rs then 1114296 else 1048688.
proof.
  by case: rs; rewrite /record_width /encoded_body_length
    /semantic_body_length /chunk_size /ceiling.
qed.

lemma final_record_width rs :
  record_width rs 0 = if rs then 184 else 112.
proof.
  by case: rs; rewrite /record_width /encoded_body_length
    /semantic_body_length /ceiling.
qed.

lemma record_width_positive rs ciphertext :
  0 <= ciphertext <= chunk_size => 112 <= record_width rs ciphertext.
proof.
  move=> hc; have hb := encoded_body_bounds rs ciphertext hc.
  by rewrite /record_width; smt().
qed.

lemma metadata_header_bounds comment :
  0 <= comment <= 99999 =>
  1 <= metadata_blocks comment <= 782 /\
  1112 <= header_length comment <= 107328.
proof.
  move=> hm.
  have hk := ceiling_128_interval (80 + comment) _; first by smt().
  by rewrite /metadata_blocks /header_length; smt().
qed.

lemma canonical_count_quotient length :
  uint64_domain length =>
  canonical_count length = length %/ chunk_size +
    (if length %% chunk_size = 0 then 0 else 1).
proof.
  move=> hl; have hc := canonical_count_contract length hl.
  by move: hc; rewrite /count_contract; smt().
qed.

lemma data_prefix_nonnegative length rs :
  uint64_domain length => 0 <= data_prefix length rs.
proof.
  move=> hl.
  have hl0 : 0 <= length by move: hl; rewrite /uint64_domain; smt().
  have hq := divz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hr0 := modz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hr1 := ltz_pmod length chunk_size _; first by rewrite /chunk_size.
  have hb := record_width_positive rs (length %% chunk_size) _.
  + by smt().
  by rewrite /data_prefix full_record_width; case: rs; smt().
qed.

lemma payload_length_positive length rs :
  uint64_domain length => 112 <= payload_length length rs.
proof.
  move=> hl; have hp := data_prefix_nonnegative length rs hl.
  by rewrite /payload_length final_record_width; case: rs; smt().
qed.

lemma payload_length_nonrs length :
  uint64_domain length =>
  payload_length length false = length + 112 * (canonical_count length + 1).
proof.
  move=> hl.
  have hn := canonical_count_quotient length hl.
  have he := divz_eq length chunk_size.
  rewrite /payload_length /data_prefix full_record_width final_record_width /=
    /record_width /encoded_body_length /semantic_body_length /=.
  by move: hn he; rewrite /chunk_size; smt().
qed.

lemma payload_length_rs length :
  payload_length length true = (length %/ chunk_size) * 1114296 +
    (if length %% chunk_size = 0 then 0
     else 48 + 136 * ceiling (length %% chunk_size + 64) 128) + 184.
proof.
  by rewrite /payload_length /data_prefix full_record_width final_record_width /=
    /record_width /encoded_body_length /semantic_body_length.
qed.

lemma record_offset_nonrs length index :
  uint64_domain length => 0 <= index <= canonical_count length =>
  record_offset length false index =
    (if index < canonical_count length then index * chunk_size else length) + 112 * index.
proof.
  move=> hl hi.
  have hp := payload_length_nonrs length hl.
  rewrite /record_offset.
  case (index < canonical_count length) => hd /=.
  + rewrite full_record_width /= /chunk_size; ring.
  by move: hp; rewrite /payload_length final_record_width /=; smt().
qed.

lemma last_data_prefix length rs :
  uint64_domain length => 0 < length =>
  data_prefix length rs =
    (canonical_count length - 1) * record_width rs chunk_size +
    record_width rs (chunk_length length (canonical_count length - 1)).
proof.
  move=> hl hp.
  have hn := canonical_count_quotient length hl.
  have he := divz_eq length chunk_size.
  have hc := last_chunk_conserves_length length hl hp.
  rewrite /data_prefix.
  case (length %% chunk_size = 0) => hr /=.
  + have hlast : chunk_length length (canonical_count length - 1) = chunk_size.
    + by move: hn he hc; rewrite /chunk_size; smt().
    rewrite hlast !full_record_width.
    by case: rs; move: hn; rewrite hr /=; smt().
  have hlast : chunk_length length (canonical_count length - 1) = length %% chunk_size.
  + by move: hn he hc; rewrite /chunk_size; smt().
  rewrite hlast !full_record_width.
  by case: rs; move: hn; rewrite hr /=; smt().
qed.

lemma record_body_bounds length index :
  uint64_domain length => 0 <= index <= canonical_count length =>
  0 <= record_body_length length index <= chunk_size.
proof.
  move=> hl hi; rewrite /record_body_length.
  case (index = canonical_count length) => hf /=; first by rewrite /chunk_size.
  have hc := canonical_chunk_bounds length index hl _; first by smt().
  by smt().
qed.

lemma record_offset_final length rs :
  record_offset length rs (canonical_count length) = data_prefix length rs.
proof. by rewrite /record_offset ltzz. qed.

lemma final_record_end length rs :
  record_offset length rs (canonical_count length) +
  record_width rs (record_body_length length (canonical_count length)) =
  payload_length length rs.
proof. by rewrite record_offset_final /record_body_length /payload_length /=. qed.

lemma adjacent_record_extents length rs index :
  uint64_domain length => 0 <= index < canonical_count length =>
  record_offset length rs index + record_width rs (record_body_length length index) =
  record_offset length rs (index + 1).
proof.
  move=> hl hi.
  have hstart : record_offset length rs index = index * record_width rs chunk_size
    by rewrite /record_offset; smt().
  have hbody : record_body_length length index = chunk_length length index
    by rewrite /record_body_length; smt().
  case (index + 1 < canonical_count length) => hn.
  + have hfull := preceding_chunks_full length index hl _; first by smt().
    rewrite hstart hbody hfull /record_offset hn /=; ring.
  have hp : 0 < length.
  + have hz := canonical_count_zero_iff length hl.
    by move: hl; rewrite /uint64_domain; smt().
  have hlast := last_data_prefix length rs hl hp.
  have hiLast : index = canonical_count length - 1 by smt().
  have hnext : index + 1 = canonical_count length by smt().
  by rewrite hstart hbody hnext record_offset_final hiLast hlast.
qed.

lemma record_offset_first length rs :
  uint64_domain length => record_offset length rs 0 = 0.
proof.
  move=> hl.
  have hb := canonical_count_bound length hl.
  have hz := canonical_count_zero_iff length hl.
  rewrite /record_offset.
  case (0 < canonical_count length) => hn /=; first by done.
  have hzero : length = 0 by smt().
  by rewrite hzero /data_prefix div0z mod0z /=.
qed.

lemma record_offset_bounds length rs index :
  uint64_domain length => 0 <= index <= canonical_count length =>
  0 <= record_offset length rs index <= data_prefix length rs.
proof.
  move=> hl hi.
  have hd := data_prefix_nonnegative length rs hl.
  case (index < canonical_count length) => hdata.
  + have hp : 0 < length.
    + have hz := canonical_count_zero_iff length hl.
      by move: hl; rewrite /uint64_domain; smt().
    have hlast := last_data_prefix length rs hl hp.
    have hc := last_chunk_conserves_length length hl hp.
    have hw := record_width_positive rs
      (chunk_length length (canonical_count length - 1)) _.
    + by smt().
    rewrite /record_offset hdata /= full_record_width.
    by move: hlast hw; rewrite full_record_width; case: rs; smt().
  by rewrite /record_offset hdata /=; smt().
qed.

lemma record_extent_bounds length rs index :
  uint64_domain length => 0 <= index <= canonical_count length =>
  0 <= record_offset length rs index /\
  record_offset length rs index <
    record_offset length rs index + record_width rs (record_body_length length index) /\
  record_offset length rs index + record_width rs (record_body_length length index) <=
    payload_length length rs.
proof.
  move=> hl hi.
  have ho := record_offset_bounds length rs index hl hi.
  have hc := record_body_bounds length index hl hi.
  have hw := record_width_positive rs (record_body_length length index) hc.
  have hd : data_prefix length rs <= payload_length length rs.
  + by rewrite /payload_length final_record_width; case: rs; smt().
  case (index = canonical_count length) => hf.
  + have he := final_record_end length rs.
    by rewrite hf; smt().
  have hn : 0 <= index + 1 <= canonical_count length by smt().
  have he := adjacent_record_extents length rs index hl _; first by smt().
  have hnext := record_offset_bounds length rs (index + 1) hl hn.
  by smt().
qed.

lemma ordered_record_extents length rs i j :
  uint64_domain length =>
  0 <= i < j <= canonical_count length =>
  record_offset length rs i + record_width rs (record_body_length length i) <=
    record_offset length rs j.
proof.
  move=> hl hi.
  have hf : 0 <= i < canonical_count length by smt().
  have he := adjacent_record_extents length rs i hl hf.
  case (j < canonical_count length) => hs.
  + have hn : i + 1 < canonical_count length by smt().
    rewrite he /record_offset hn hs /= !full_record_width.
    by case: rs; smt().
  have hlast : j = canonical_count length by smt().
  have hn : 0 <= i + 1 <= canonical_count length by smt().
  have hb := record_offset_bounds length rs (i + 1) hl hn.
  by rewrite he hlast record_offset_final; smt().
qed.

lemma canonical_slot_body_length commitment length index :
  uint64_domain length => 0 <= index <= canonical_count length =>
  (nth witness (canonical_profile commitment length) index).`4 =
    record_body_length length index.
proof.
  move=> hl hi.
  by rewrite (canonical_profile_slot commitment length index hl hi)
    /canonical_slot /record_body_length /=.
qed.

lemma record_body_matches_counter_domain length index :
  record_body_length length index = normal_record_length length index.
proof. by rewrite /record_body_length /normal_record_length. qed.

lemma canonical_record_counter_separation prefix length i j counter :
  size prefix = 8 => uint64_domain length =>
  0 <= i <= canonical_count length => 0 <= j <= canonical_count length =>
  i <> j =>
  !(serpent_uses prefix i (record_body_length length i) counter /\
    serpent_uses prefix j (record_body_length length j) counter).
proof.
  move=> hp hl hf hs hd.
  rewrite !record_body_matches_counter_domain.
  by apply normal_used_intervals_disjoint.
qed.

op descriptor_offset (header length : int) (rs : bool) (index : int) : int =
  header + record_offset length rs index.
op body_offset (header length : int) (rs : bool) (index : int) : int =
  descriptor_offset header length rs index + 48.
op record_end (header length : int) (rs : bool) (index : int) : int =
  body_offset header length rs index +
    encoded_body_length rs (record_body_length length index).

lemma record_host_extents header length rs index :
  uint64_domain length => 0 <= index <= canonical_count length => 0 <= header =>
  header + payload_length length rs <= max_int64 =>
  0 <= descriptor_offset header length rs index <= max_int64 /\
  0 <= body_offset header length rs index <= max_int64 /\
  record_end header length rs index <= header + payload_length length rs /\
  (index = canonical_count length =>
    record_end header length rs index = header + payload_length length rs).
proof.
  move=> hl hi hh hfile.
  have he := record_extent_bounds length rs index hl hi.
  have hc := record_body_bounds length index hl hi.
  have hb := encoded_body_bounds rs (record_body_length length index) hc.
  have hf := final_record_end length rs.
  rewrite /descriptor_offset /body_offset /record_end /descriptor_offset /=.
  by move: he hf; rewrite /record_width; smt().
qed.

lemma record_buffers_fit_int32 length index rs :
  uint64_domain length => 0 <= index <= canonical_count length =>
  0 <= encoded_body_length rs (record_body_length length index) <= 2147483647 /\
  0 <= decoded_body_length rs (record_body_length length index) <= 2147483647.
proof.
  move=> hl hi.
  have hc := record_body_bounds length index hl hi.
  have he := encoded_body_bounds rs (record_body_length length index) hc.
  have hd := decoded_body_bounds rs (record_body_length length index) hc.
  by smt().
qed.

lemma normal_record_host_extents length comment rs index :
  uint64_domain length => 0 <= comment <= 99999 =>
  0 <= index <= canonical_count length => file_length length comment rs <= max_int64 =>
  0 <= descriptor_offset (header_length comment) length rs index <= max_int64 /\
  0 <= body_offset (header_length comment) length rs index <= max_int64 /\
  record_end (header_length comment) length rs index <= backup_offset length comment rs /\
  (index = canonical_count length =>
    record_end (header_length comment) length rs index = backup_offset length comment rs).
proof.
  move=> hl hm hi hf.
  have hh := metadata_header_bounds comment hm.
  have hheader : 0 <= header_length comment by smt().
  have hfile : header_length comment + payload_length length rs + 1008 <= max_int64
    by move: hf; rewrite /file_length /backup_offset.
  have hbackup : header_length comment + payload_length length rs <= max_int64
    by smt().
  have he := record_host_extents (header_length comment) length rs index hl hi hheader hbackup.
  by rewrite /backup_offset; exact he.
qed.

lemma suffix_geometry length comment rs :
  trailer_offset length comment rs = backup_offset length comment rs + 960 /\
  file_length length comment rs = trailer_offset length comment rs + 48.
proof. rewrite /trailer_offset /file_length; split; ring. qed.

lemma rs_ceiling_boundary :
  encoded_body_length true 64 = 136 /\ encoded_body_length true 65 = 272.
proof. by rewrite /encoded_body_length /semantic_body_length /ceiling. qed.

lemma empty_payload_has_final rs :
  payload_length 0 rs = if rs then 184 else 112.
proof. by rewrite /payload_length /data_prefix div0z mod0z /= final_record_width. qed.

import StdOrder.IntOrder.

(* Word-model folds preserve explicit early zeroes and final wrapped results.
   Relating these predicates to Go source remains a separate checked interface. *)
op payload_valid_count (length count : int) : bool =
  count = canonical_count length /\ count < maximum_record_count.

op encoded_body_execution (ciphertext : int) (rs : bool) : int * bool =
  let semantic = checked_add ciphertext 64 in
  if !semantic.`2 then (0, false)
  else if !rs then (semantic.`1, true)
  else let blocks = checked_ceil_div semantic.`1 128 in
    if !blocks.`2 then (0, false) else checked_mul blocks.`1 136.

op encoded_body_result (ciphertext : int) (rs : bool) : int * bool =
  (if uint64_modulus <= semantic_body_length ciphertext then 0
   else encoded_body_length rs ciphertext %% uint64_modulus,
   encoded_body_length rs ciphertext < uint64_modulus).

op encoded_body_source_contract (ciphertext : int) (rs : bool)
    (result : int) (ok : bool) : bool =
  uint64_domain result /\ (result, ok) = encoded_body_result ciphertext rs.

lemma add_word_equation a b :
  uint64_domain a => uint64_domain b =>
  checked_add a b = ((a + b) %% uint64_modulus, a + b < uint64_modulus).
proof.
  move=> ha hb; have h := checked_add_source_contract a b ha hb.
  by move: h; rewrite /add_source_contract; smt().
qed.

lemma mul_word_equation a b :
  uint64_domain a => uint64_domain b =>
  checked_mul a b = ((a * b) %% uint64_modulus, a * b < uint64_modulus).
proof.
  move=> ha hb; have h := checked_mul_source_contract a b ha hb.
  by move: h; rewrite /mul_source_contract; smt().
qed.

lemma semantic_le_encoded rs ciphertext :
  0 <= ciphertext => semantic_body_length ciphertext <= encoded_body_length rs ciphertext.
proof.
  move=> hc.
  have h := ceiling_128_interval (semantic_body_length ciphertext) _.
  + by rewrite /semantic_body_length; smt().
  by case: rs; rewrite /encoded_body_length /=; smt().
qed.

lemma encoded_body_ghost_formula rs ciphertext :
  encoded_body_length rs ciphertext =
    if rs then 136 * ((ciphertext + 64) %/ 128 +
      (if (ciphertext + 64) %% 128 = 0 then 0 else 1)) else ciphertext + 64.
proof. by rewrite /encoded_body_length /semantic_body_length /ceiling. qed.

lemma data_prefix_nonrs length :
  uint64_domain length => data_prefix length false = length + canonical_count length * 112.
proof.
  move=> hl; have h := payload_length_nonrs length hl.
  by move: h; rewrite /payload_length final_record_width /=; smt().
qed.

lemma data_prefix_ghost_formula length rs :
  uint64_domain length =>
  data_prefix length rs =
    if rs then (length %/ chunk_size) * 1114296 +
      (if length %% chunk_size = 0 then 0
       else 48 + encoded_body_length true (length %% chunk_size))
    else length + (length %/ chunk_size +
      (if length %% chunk_size = 0 then 0 else 1)) * 112.
proof.
  move=> hl.
  case: rs => /=.
  + by rewrite /data_prefix full_record_width /= /record_width.
  by rewrite (data_prefix_nonrs length hl) (canonical_count_quotient length hl).
qed.

lemma payload_valid_ghost_formula length count :
  uint64_domain length =>
  payload_valid_count length count =
    (count = length %/ chunk_size +
      (if length %% chunk_size = 0 then 0 else 1) /\ count < maximum_record_count).
proof. by move=> hl; rewrite /payload_valid_count (canonical_count_quotient length hl). qed.

lemma encoded_body_execution_closed_form ciphertext rs :
  uint64_domain ciphertext =>
  encoded_body_execution ciphertext rs = encoded_body_result ciphertext rs.
proof.
  move=> hc.
  have hc0 : 0 <= ciphertext by move: hc; rewrite /uint64_domain; smt().
  have h64 : uint64_domain 64 by rewrite /uint64_domain /uint64_modulus.
  have h128 : uint64_domain 128 by rewrite /uint64_domain /uint64_modulus.
  have h136 : uint64_domain 136 by rewrite /uint64_domain /uint64_modulus.
  have hencoded := semantic_le_encoded rs ciphertext hc0.
  rewrite /encoded_body_execution (add_word_equation ciphertext 64 hc h64) /=.
  case (ciphertext + 64 < uint64_modulus) => hs /=.
  + have hsemantic : uint64_domain (ciphertext + 64)
      by rewrite /uint64_domain; smt().
    have hmod : (ciphertext + 64) %% uint64_modulus = ciphertext + 64
      by apply pmod_small; smt().
    rewrite hmod.
    case: rs hencoded => /= hencoded.
    + have hceil := checked_ceil_div_contract (ciphertext + 64) 128 hsemantic h128 _.
      + by done.
      have hblocks : uint64_domain (ceiling (ciphertext + 64) 128) by smt().
      have hpair : checked_ceil_div (ciphertext + 64) 128 =
          (ceiling (ciphertext + 64) 128, true) by smt().
      rewrite hpair /= (mul_word_equation _ _ hblocks h136).
      by rewrite /encoded_body_result /encoded_body_length /semantic_body_length /=; smt().
    rewrite /encoded_body_result /encoded_body_length /semantic_body_length /=.
    by smt().
  rewrite /encoded_body_result /semantic_body_length.
  by smt().
qed.

lemma encoded_body_result_range ciphertext rs :
  uint64_domain (encoded_body_result ciphertext rs).`1.
proof.
  rewrite /encoded_body_result /=.
  case (uint64_modulus <= semantic_body_length ciphertext) => hs /=.
  + by rewrite /uint64_domain /uint64_modulus.
  exact (low_word_range (encoded_body_length rs ciphertext)).
qed.

lemma encoded_body_execution_source_contract ciphertext rs :
  uint64_domain ciphertext =>
  encoded_body_source_contract ciphertext rs (encoded_body_execution ciphertext rs).`1
    (encoded_body_execution ciphertext rs).`2.
proof.
  move=> hc.
  have hr := encoded_body_result_range ciphertext rs.
  by rewrite /encoded_body_source_contract (encoded_body_execution_closed_form ciphertext rs hc).
qed.

lemma encoded_body_source_contract_refines_model ciphertext rs result ok :
  uint64_domain ciphertext => encoded_body_source_contract ciphertext rs result ok =>
  (result, ok) = encoded_body_execution ciphertext rs.
proof.
  by move=> hc [_ ->]; rewrite (encoded_body_execution_closed_form ciphertext rs hc).
qed.

lemma encoded_body_source_contract_unique ciphertext rs result1 result2 ok1 ok2 :
  encoded_body_source_contract ciphertext rs result1 ok1 =>
  encoded_body_source_contract ciphertext rs result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof. by rewrite /encoded_body_source_contract; smt(). qed.

lemma encoded_body_bounded_success ciphertext rs :
  0 <= ciphertext <= chunk_size =>
  encoded_body_execution ciphertext rs = (encoded_body_length rs ciphertext, true).
proof.
  move=> hc.
  have hword : uint64_domain ciphertext
    by move: hc; rewrite /uint64_domain /uint64_modulus /chunk_size; smt().
  have he := encoded_body_bounds rs ciphertext hc.
  have hs : semantic_body_length ciphertext < uint64_modulus
    by move: hc; rewrite /semantic_body_length /chunk_size /uint64_modulus; smt().
  have hmod : encoded_body_length rs ciphertext %% uint64_modulus = encoded_body_length rs ciphertext.
  + apply pmod_small; move: he; rewrite /uint64_modulus; smt().
  rewrite (encoded_body_execution_closed_form ciphertext rs hword) /encoded_body_result.
  by move: he; rewrite /uint64_modulus; smt().
qed.

op rs_data_execution (length : int) : int * bool =
  let base = checked_mul (length %/ chunk_size) 1114296 in
  if !base.`2 then (0, false)
  else if length %% chunk_size = 0 then base
  else let encoded = encoded_body_execution (length %% chunk_size) true in
    if !encoded.`2 then (0, false)
    else let width = checked_add 48 encoded.`1 in
      if !width.`2 then (0, false)
      else let combined = checked_add base.`1 width.`1 in
        if !combined.`2 then (0, false) else combined.

op payload_execution (length count : int) (rs : bool) : int * bool =
  if !payload_valid_count length count then (0, false)
  else if !rs then
    let with_final = checked_add count 1 in
    if !with_final.`2 then (0, false)
    else let overhead = checked_mul with_final.`1 112 in
      if !overhead.`2 then (0, false) else checked_add length overhead.`1
  else let data = rs_data_execution length in
    if !data.`2 then (0, false) else checked_add data.`1 184.

op payload_result (length count : int) (rs : bool) : int * bool =
  (if !payload_valid_count length count \/
      (rs /\ uint64_modulus <= data_prefix length rs) then 0
   else payload_length length rs %% uint64_modulus,
   payload_valid_count length count /\ payload_length length rs < uint64_modulus).

op payload_source_contract (length count : int) (rs : bool)
    (result : int) (ok : bool) : bool =
  uint64_domain result /\ (result, ok) = payload_result length count rs.

lemma add_word_fits a b :
  uint64_domain a => uint64_domain b => a + b < uint64_modulus =>
  checked_add a b = (a + b, true).
proof.
  move=> ha hb hfit.
  have hmod : (a + b) %% uint64_modulus = a + b
    by apply pmod_small; move: ha hb; rewrite /uint64_domain; smt().
  by rewrite (add_word_equation a b ha hb) hmod; smt().
qed.

lemma mul_word_fits a b :
  uint64_domain a => uint64_domain b => a * b < uint64_modulus =>
  checked_mul a b = (a * b, true).
proof.
  move=> ha hb hfit.
  have hpositive : 0 <= a * b
    by apply mulr_ge0; move: ha hb; rewrite /uint64_domain; smt().
  have hmod : (a * b) %% uint64_modulus = a * b by apply pmod_small; smt().
  by rewrite (mul_word_equation a b ha hb) hmod; smt().
qed.

lemma rs_data_execution_closed_form length :
  uint64_domain length =>
  rs_data_execution length =
    if data_prefix length true < uint64_modulus
    then (data_prefix length true, true) else (0, false).
proof.
  move=> hl.
  have hq0 := divz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hqle := leq_div length chunk_size _ _.
  + by move: hl; rewrite /uint64_domain; smt().
  + by rewrite /chunk_size.
  have hq : uint64_domain (length %/ chunk_size)
    by move: hl; rewrite /uint64_domain; smt().
  have hf : uint64_domain 1114296 by rewrite /uint64_domain /uint64_modulus.
  have hr0 := modz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hr1 := ltz_pmod length chunk_size _; first by rewrite /chunk_size.
  have hr : 0 <= length %% chunk_size <= chunk_size by smt().
  have he := encoded_body_bounds true (length %% chunk_size) hr.
  have hd : data_prefix length true =
      (length %/ chunk_size) * 1114296 +
      (if length %% chunk_size = 0 then 0
       else 48 + encoded_body_length true (length %% chunk_size)).
  + by rewrite /data_prefix full_record_width /= /record_width.
  rewrite /rs_data_execution (mul_word_equation _ _ hq hf) /=.
  case ((length %/ chunk_size) * 1114296 < uint64_modulus) => hbase /=.
  + have hb0 : 0 <= (length %/ chunk_size) * 1114296 by smt().
    have hbase_mod : ((length %/ chunk_size) * 1114296) %% uint64_modulus =
        (length %/ chunk_size) * 1114296 by apply pmod_small; smt().
    rewrite hbase_mod.
    case (length %% chunk_size = 0) => hrzero /=.
    + by smt().
    rewrite (encoded_body_bounded_success _ true hr) /=.
    have h48 : uint64_domain 48 by rewrite /uint64_domain /uint64_modulus.
    have hencoded : uint64_domain (encoded_body_length true (length %% chunk_size))
      by move: he; rewrite /uint64_domain /uint64_modulus; smt().
    have hwidth : 48 + encoded_body_length true (length %% chunk_size) < uint64_modulus
      by move: he; rewrite /uint64_modulus; smt().
    rewrite (add_word_fits _ _ h48 hencoded hwidth) /=.
    have hbase_word : uint64_domain ((length %/ chunk_size) * 1114296)
      by rewrite /uint64_domain; smt().
    have hwidth_word : uint64_domain (48 + encoded_body_length true (length %% chunk_size))
      by rewrite /uint64_domain; smt().
    rewrite (add_word_equation _ _ hbase_word hwidth_word) /=.
    have hsum : (length %/ chunk_size) * 1114296 +
        (48 + encoded_body_length true (length %% chunk_size)) = data_prefix length true
      by smt().
    rewrite hsum.
    case (data_prefix length true < uint64_modulus) => hfit /=.
    + have hpositive := data_prefix_nonnegative length true hl.
      by rewrite pmod_small; smt().
    by done.
  by smt().
qed.

lemma payload_execution_closed_form length count rs :
  uint64_domain length => uint64_domain count =>
  payload_execution length count rs = payload_result length count rs.
proof.
  move=> hl hc.
  rewrite /payload_execution.
  case (payload_valid_count length count) => hv /=.
  + have hcount : count = canonical_count length by move: hv; rewrite /payload_valid_count; smt().
    have hbound := canonical_count_bound length hl.
    case: rs => /=.
    + rewrite (rs_data_execution_closed_form length hl).
      have h184 : uint64_domain 184 by rewrite /uint64_domain /uint64_modulus.
      have hdata := data_prefix_nonnegative length true hl.
      have htotal : payload_length length true = data_prefix length true + 184
        by rewrite /payload_length final_record_width.
      case (data_prefix length true < uint64_modulus) => hd /=.
      + have hdword : uint64_domain (data_prefix length true) by rewrite /uint64_domain; smt().
        rewrite (add_word_equation _ _ hdword h184).
        by rewrite /payload_result /= hv; smt().
      by rewrite /payload_result /= hv; smt().
    have h1 : uint64_domain 1 by rewrite /uint64_domain /uint64_modulus.
    have hfinal : count + 1 < uint64_modulus
      by move: hc hbound; rewrite /uint64_domain /reachable_count_bound /uint64_modulus; smt().
    rewrite (add_word_fits count 1 hc h1 hfinal) /=.
    have hfinal_word : uint64_domain (count + 1) by rewrite /uint64_domain; smt().
    have h112 : uint64_domain 112 by rewrite /uint64_domain /uint64_modulus.
    have hoverhead : (count + 1) * 112 < uint64_modulus
      by move: hbound; rewrite /reachable_count_bound /uint64_modulus; smt().
    rewrite (mul_word_fits _ _ hfinal_word h112 hoverhead) /=.
    have howord : uint64_domain ((count + 1) * 112)
      by move: hc; rewrite /uint64_domain; smt().
    rewrite (add_word_equation _ _ hl howord).
    have hp := payload_length_nonrs length hl.
    by rewrite /payload_result /= hv; smt().
  by rewrite /payload_result /= hv.
qed.

lemma payload_result_range length count rs :
  uint64_domain (payload_result length count rs).`1.
proof.
  rewrite /payload_result /=.
  case (!payload_valid_count length count \/
      (rs /\ uint64_modulus <= data_prefix length rs)) => hs /=.
  + by rewrite /uint64_domain /uint64_modulus.
  exact (low_word_range (payload_length length rs)).
qed.

lemma payload_execution_source_contract length count rs :
  uint64_domain length => uint64_domain count =>
  payload_source_contract length count rs (payload_execution length count rs).`1
    (payload_execution length count rs).`2.
proof.
  move=> hl hc.
  have hr := payload_result_range length count rs.
  by rewrite /payload_source_contract (payload_execution_closed_form length count rs hl hc).
qed.

lemma payload_source_contract_refines_model length count rs result ok :
  uint64_domain length => uint64_domain count =>
  payload_source_contract length count rs result ok =>
  (result, ok) = payload_execution length count rs.
proof.
  by move=> hl hc [_ ->]; rewrite (payload_execution_closed_form length count rs hl hc).
qed.

lemma payload_source_contract_unique length count rs result1 result2 ok1 ok2 :
  payload_source_contract length count rs result1 ok1 =>
  payload_source_contract length count rs result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof. by rewrite /payload_source_contract; smt(). qed.

lemma encoded_body_source_contract_fields ciphertext rs result ok :
  encoded_body_source_contract ciphertext rs result ok =
    (uint64_domain result /\
     result = (if uint64_modulus <= semantic_body_length ciphertext then 0
       else encoded_body_length rs ciphertext %% uint64_modulus) /\
     ok = (encoded_body_length rs ciphertext < uint64_modulus)).
proof. by rewrite /encoded_body_source_contract /encoded_body_result; smt(). qed.

lemma payload_source_contract_fields length count rs result ok :
  payload_source_contract length count rs result ok =
    (uint64_domain result /\
     result = (if !payload_valid_count length count \/
         (rs /\ uint64_modulus <= data_prefix length rs) then 0
       else payload_length length rs %% uint64_modulus) /\
     ok = (payload_valid_count length count /\ payload_length length rs < uint64_modulus)).
proof. by rewrite /payload_source_contract /payload_result; smt(). qed.

lemma payload_total_ghost_formula length rs :
  uint64_domain length =>
  payload_length length rs =
    (if rs then (length %/ chunk_size) * 1114296 +
      (if length %% chunk_size = 0 then 0
       else 48 + encoded_body_length true (length %% chunk_size))
     else length + (length %/ chunk_size +
       (if length %% chunk_size = 0 then 0 else 1)) * 112) +
    (if rs then 184 else 112).
proof.
  by move=> hl; rewrite /payload_length final_record_width (data_prefix_ghost_formula length rs hl).
qed.

lemma encoded_body_source_contract_bounded_success ciphertext rs result ok :
  0 <= ciphertext <= chunk_size => encoded_body_source_contract ciphertext rs result ok =>
  (result, ok) = (encoded_body_length rs ciphertext, true).
proof.
  move=> hc hsource.
  have hword : uint64_domain ciphertext
    by move: hc; rewrite /uint64_domain /uint64_modulus /chunk_size; smt().
  have hm := encoded_body_source_contract_refines_model ciphertext rs result ok hword hsource.
  have hs := encoded_body_bounded_success ciphertext rs hc.
  by smt().
qed.

lemma payload_execution_fits length count rs :
  uint64_domain length => uint64_domain count => payload_valid_count length count =>
  payload_length length rs < uint64_modulus =>
  payload_execution length count rs = (payload_length length rs, true).
proof.
  move=> hl hc hv hf.
  have hp := payload_length_positive length rs hl.
  have hd : data_prefix length rs <= payload_length length rs.
  + by rewrite /payload_length final_record_width; case: rs; smt().
  have hmod : payload_length length rs %% uint64_modulus = payload_length length rs
    by apply pmod_small; smt().
  rewrite (payload_execution_closed_form length count rs hl hc) /payload_result hv /=.
  by smt().
qed.

lemma payload_source_contract_success length count rs result ok :
  uint64_domain length => uint64_domain count =>
  payload_source_contract length count rs result ok => ok =>
  payload_valid_count length count /\ result = payload_length length rs.
proof.
  move=> hl hc hsource hok.
  have hfields := payload_source_contract_fields length count rs result ok.
  have hv : payload_valid_count length count by smt().
  have hf : payload_length length rs < uint64_modulus by smt().
  have hm := payload_source_contract_refines_model length count rs result ok hl hc hsource.
  have hs := payload_execution_fits length count rs hl hc hv hf.
  by smt().
qed.

lemma payload_source_contract_host_success length count comment rs result ok :
  uint64_domain length => count = canonical_count length => 0 <= comment <= 99999 =>
  file_length length comment rs <= max_int64 =>
  payload_source_contract length count rs result ok =>
  (result, ok) = (payload_length length rs, true).
proof.
  move=> hl hc hm hf hsource.
  have hcount := canonical_count_bound length hl.
  have hcword : uint64_domain count
    by move: hcount; rewrite /uint64_domain /uint64_modulus /reachable_count_bound; smt().
  have hv : payload_valid_count length count
    by move: hcount; rewrite /payload_valid_count /reachable_count_bound /maximum_record_count; smt().
  have hh := metadata_header_bounds comment hm.
  have hfit : payload_length length rs < uint64_modulus.
  + by move: hf hh; rewrite /file_length /backup_offset /max_int64 /uint64_modulus; smt().
  have href := payload_source_contract_refines_model length count rs result ok hl hcword hsource.
  have hsuccess := payload_execution_fits length count rs hl hcword hv hfit.
  by smt().
qed.

lemma encoded_final_multiply_wrap_witness :
  encoded_body_execution 17361641481138401345 true = (16, false).
proof.
  have hc : uint64_domain 17361641481138401345 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (encoded_body_execution_closed_form _ true hc) /encoded_body_result
    /encoded_body_length /semantic_body_length /ceiling /uint64_modulus.
qed.

lemma encoded_early_zero_witness :
  encoded_body_execution max_uint64 true = (0, false) /\
  encoded_body_length true max_uint64 %% uint64_modulus = 1152921504606847112.
proof.
  have hc : uint64_domain max_uint64 by rewrite /uint64_domain /uint64_modulus /max_uint64.
  by rewrite (encoded_body_execution_closed_form _ true hc) /encoded_body_result
    /encoded_body_length /semantic_body_length /ceiling /uint64_modulus /max_uint64.
qed.

lemma encoded_rs65_witness :
  encoded_body_execution 65 true = (272, true) /\
  encoded_body_execution 65 true <> (136, true).
proof.
  have hc : 0 <= 65 <= chunk_size by rewrite /chunk_size.
  by rewrite (encoded_body_bounded_success 65 true hc)
    /encoded_body_length /semantic_body_length /ceiling.
qed.

lemma payload_final_add_wrap_witness :
  payload_execution 17358774610905959105 16554617510706 true = (88, false).
proof.
  have hn : uint64_domain 17358774610905959105 by rewrite /uint64_domain /uint64_modulus.
  have hc : uint64_domain 16554617510706 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (payload_execution_closed_form _ _ true hn hc) /payload_result /payload_valid_count
    /canonical_count /payload_length /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /maximum_record_count /uint64_modulus.
qed.

lemma payload_rs_early_zero_witness :
  payload_execution max_uint64 reachable_count_bound true = (0, false) /\
  payload_length max_uint64 true %% uint64_modulus = 1156158466839019704.
proof.
  have hn : uint64_domain max_uint64 by rewrite /uint64_domain /uint64_modulus /max_uint64.
  have hc : uint64_domain reachable_count_bound
    by rewrite /uint64_domain /uint64_modulus /reachable_count_bound.
  by rewrite (payload_execution_closed_form _ _ true hn hc) /payload_result /payload_valid_count
    /canonical_count /payload_length /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /maximum_record_count /uint64_modulus
    /max_uint64 /reachable_count_bound.
qed.

lemma payload_nonrs_wrapped_refusal_witness :
  payload_execution max_uint64 reachable_count_bound false = (1970324836974703, false).
proof.
  have hn : uint64_domain max_uint64 by rewrite /uint64_domain /uint64_modulus /max_uint64.
  have hc : uint64_domain reachable_count_bound
    by rewrite /uint64_domain /uint64_modulus /reachable_count_bound.
  by rewrite (payload_execution_closed_form _ _ false hn hc) /payload_result /payload_valid_count
    /canonical_count /payload_length /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /maximum_record_count /uint64_modulus
    /max_uint64 /reachable_count_bound.
qed.

lemma payload_invalid_count_witness rs : payload_execution 0 1 rs = (0, false).
proof. by rewrite /payload_execution /payload_valid_count canonical_count_zero. qed.

(* The raw offset helper validates neither count nor index; its >=count branch
   must retain its own early-zero/final-wrap behavior before caller refinement. *)
op offset_math (length count : int) (rs : bool) (index : int) : int =
  if rs then (if index < count then index * 1114296 else data_prefix length true)
  else (if index < count then index * chunk_size else length) + index * 112.

op offset_early_zero (length count : int) (rs : bool) (index : int) : bool =
  if rs then !(index < count) /\ uint64_modulus <= (length %/ chunk_size) * 1114296
  else (index < count /\ uint64_modulus <= index * chunk_size) \/
    uint64_modulus <= index * 112.

op rs_final_offset_execution (length : int) : int * bool =
  let base = checked_mul (length %/ chunk_size) 1114296 in
  if !base.`2 then (0, false)
  else if length %% chunk_size = 0 then (base.`1, true)
  else let encoded = encoded_body_execution (length %% chunk_size) true in
    if !encoded.`2 then (0, false)
    else let width = checked_add 48 encoded.`1 in
      if !width.`2 then (0, false) else checked_add base.`1 width.`1.

op record_offset_execution (length count : int) (rs : bool) (index : int) : int * bool =
  if !rs then
    let before = if index < count then checked_mul index chunk_size else (length, true) in
    if !before.`2 then (0, false)
    else let overhead = checked_mul index 112 in
      if !overhead.`2 then (0, false) else checked_add before.`1 overhead.`1
  else if index < count then checked_mul index 1114296
  else rs_final_offset_execution length.

op offset_result (length count : int) (rs : bool) (index : int) : int * bool =
  (if offset_early_zero length count rs index then 0
   else offset_math length count rs index %% uint64_modulus,
   offset_math length count rs index < uint64_modulus).

op offset_source_contract (length count : int) (rs : bool) (index result : int)
    (ok : bool) : bool =
  uint64_domain result /\ (result, ok) = offset_result length count rs index.

lemma rs_final_offset_execution_closed_form length :
  uint64_domain length =>
  rs_final_offset_execution length =
    (if uint64_modulus <= (length %/ chunk_size) * 1114296 then 0
     else data_prefix length true %% uint64_modulus,
     data_prefix length true < uint64_modulus).
proof.
  move=> hl.
  have hq0 := divz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hqle := leq_div length chunk_size _ _.
  + by move: hl; rewrite /uint64_domain; smt().
  + by rewrite /chunk_size.
  have hq : uint64_domain (length %/ chunk_size)
    by move: hl; rewrite /uint64_domain; smt().
  have hf : uint64_domain 1114296 by rewrite /uint64_domain /uint64_modulus.
  have hr0 := modz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hr1 := ltz_pmod length chunk_size _; first by rewrite /chunk_size.
  have hr : 0 <= length %% chunk_size <= chunk_size by smt().
  have he := encoded_body_bounds true (length %% chunk_size) hr.
  have hd : data_prefix length true = (length %/ chunk_size) * 1114296 +
      (if length %% chunk_size = 0 then 0
       else 48 + encoded_body_length true (length %% chunk_size)).
  + by rewrite /data_prefix full_record_width /= /record_width.
  rewrite /rs_final_offset_execution (mul_word_equation _ _ hq hf) /=.
  case ((length %/ chunk_size) * 1114296 < uint64_modulus) => hbase /=.
  + have hb0 : 0 <= (length %/ chunk_size) * 1114296 by smt().
    have hbase_mod : ((length %/ chunk_size) * 1114296) %% uint64_modulus =
        (length %/ chunk_size) * 1114296 by apply pmod_small; smt().
    rewrite hbase_mod.
    case (length %% chunk_size = 0) => hrzero /=.
    + by smt().
    rewrite (encoded_body_bounded_success _ true hr) /=.
    have h48 : uint64_domain 48 by rewrite /uint64_domain /uint64_modulus.
    have hencoded : uint64_domain (encoded_body_length true (length %% chunk_size))
      by move: he; rewrite /uint64_domain /uint64_modulus; smt().
    have hwidth : 48 + encoded_body_length true (length %% chunk_size) < uint64_modulus
      by move: he; rewrite /uint64_modulus; smt().
    rewrite (add_word_fits _ _ h48 hencoded hwidth) /=.
    have hbase_word : uint64_domain ((length %/ chunk_size) * 1114296)
      by rewrite /uint64_domain; smt().
    have hwidth_word : uint64_domain (48 + encoded_body_length true (length %% chunk_size))
      by rewrite /uint64_domain; smt().
    rewrite (add_word_equation _ _ hbase_word hwidth_word).
    by smt().
  by smt().
qed.

lemma record_offset_execution_closed_form length count rs index :
  uint64_domain length => uint64_domain count => uint64_domain index =>
  record_offset_execution length count rs index = offset_result length count rs index.
proof.
  move=> hl hc hi.
  have hl0 : 0 <= length by move: hl; rewrite /uint64_domain; smt().
  have hi0 : 0 <= index by move: hi; rewrite /uint64_domain; smt().
  have hm : uint64_domain chunk_size by rewrite /uint64_domain /uint64_modulus /chunk_size.
  have h112 : uint64_domain 112 by rewrite /uint64_domain /uint64_modulus.
  have hf : uint64_domain 1114296 by rewrite /uint64_domain /uint64_modulus.
  have hplain0 : 0 <= index * chunk_size by rewrite /chunk_size; smt().
  have hoverhead0 : 0 <= index * 112 by smt().
  rewrite /record_offset_execution /offset_result /offset_math /offset_early_zero.
  case: rs => /=.
  + case (index < count) => hb /=.
    + by rewrite (mul_word_equation _ _ hi hf).
    by rewrite (rs_final_offset_execution_closed_form length hl).
  case (index < count) => hb /=.
  + rewrite (mul_word_equation _ _ hi hm) /=.
    case (index * chunk_size < uint64_modulus) => hp /=.
    + have hplain_mod : (index * chunk_size) %% uint64_modulus = index * chunk_size
        by apply pmod_small; smt().
      rewrite hplain_mod (mul_word_equation _ _ hi h112) /=.
      case (index * 112 < uint64_modulus) => ho /=.
      + have hoverhead_mod : (index * 112) %% uint64_modulus = index * 112
          by apply pmod_small; smt().
        have hplain : uint64_domain (index * chunk_size) by rewrite /uint64_domain; smt().
        have hoverhead : uint64_domain (index * 112) by rewrite /uint64_domain; smt().
        rewrite hoverhead_mod (add_word_equation _ _ hplain hoverhead).
        by smt().
      by smt().
    by smt().
  rewrite (mul_word_equation _ _ hi h112) /=.
  case (index * 112 < uint64_modulus) => ho /=.
  + have hoverhead_mod : (index * 112) %% uint64_modulus = index * 112
      by apply pmod_small; smt().
    have hoverhead : uint64_domain (index * 112) by rewrite /uint64_domain; smt().
    rewrite hoverhead_mod (add_word_equation _ _ hl hoverhead).
    by smt().
  by smt().
qed.

lemma offset_result_range length count rs index :
  uint64_domain (offset_result length count rs index).`1.
proof.
  rewrite /offset_result /=.
  case (offset_early_zero length count rs index) => hz /=.
  + by rewrite /uint64_domain /uint64_modulus.
  exact (low_word_range (offset_math length count rs index)).
qed.

lemma record_offset_execution_source_contract length count rs index :
  uint64_domain length => uint64_domain count => uint64_domain index =>
  offset_source_contract length count rs index (record_offset_execution length count rs index).`1
    (record_offset_execution length count rs index).`2.
proof.
  move=> hl hc hi.
  have hr := offset_result_range length count rs index.
  by rewrite /offset_source_contract (record_offset_execution_closed_form length count rs index hl hc hi).
qed.

lemma offset_source_contract_refines_model length count rs index result ok :
  uint64_domain length => uint64_domain count => uint64_domain index =>
  offset_source_contract length count rs index result ok =>
  (result, ok) = record_offset_execution length count rs index.
proof.
  by move=> hl hc hi [_ ->]; rewrite (record_offset_execution_closed_form length count rs index hl hc hi).
qed.

lemma offset_source_contract_unique length count rs index result1 result2 ok1 ok2 :
  offset_source_contract length count rs index result1 ok1 =>
  offset_source_contract length count rs index result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof. by rewrite /offset_source_contract; smt(). qed.

lemma offset_source_contract_fields length count rs index result ok :
  offset_source_contract length count rs index result ok =
    (uint64_domain result /\
     result = (if offset_early_zero length count rs index then 0
       else offset_math length count rs index %% uint64_modulus) /\
     ok = (offset_math length count rs index < uint64_modulus)).
proof. by rewrite /offset_source_contract /offset_result; smt(). qed.

lemma offset_math_ghost_formula length count rs index :
  uint64_domain length =>
  offset_math length count rs index =
    if rs then (if index < count then index * 1114296
      else (length %/ chunk_size) * 1114296 +
        (if length %% chunk_size = 0 then 0
         else 48 + encoded_body_length true (length %% chunk_size)))
    else (if index < count then index * chunk_size else length) + index * 112.
proof.
  move=> hl.
  by rewrite /offset_math (data_prefix_ghost_formula length true hl).
qed.

lemma offset_early_ghost_formula length count rs index :
  offset_early_zero length count rs index =
    if rs then (count <= index /\ uint64_modulus <= (length %/ chunk_size) * 1114296)
    else ((index < count /\ uint64_modulus <= index * chunk_size) \/
      uint64_modulus <= index * 112).
proof. by case: rs; rewrite /offset_early_zero /=; smt(). qed.

lemma offset_math_nonnegative length count rs index :
  uint64_domain length => uint64_domain index => 0 <= offset_math length count rs index.
proof.
  move=> hl hi.
  have hl0 : 0 <= length by move: hl; rewrite /uint64_domain; smt().
  have hi0 : 0 <= index by move: hi; rewrite /uint64_domain; smt().
  have hd := data_prefix_nonnegative length true hl.
  have hplain0 : 0 <= index * chunk_size by rewrite /chunk_size; smt().
  by case: rs; rewrite /offset_math /=; smt().
qed.

lemma offset_early_cannot_fit length count rs index :
  uint64_domain length => uint64_domain index => offset_early_zero length count rs index =>
  uint64_modulus <= offset_math length count rs index.
proof.
  move=> hl hi hz.
  have hl0 : 0 <= length by move: hl; rewrite /uint64_domain; smt().
  have hi0 : 0 <= index by move: hi; rewrite /uint64_domain; smt().
  have hplain0 : 0 <= index * chunk_size by rewrite /chunk_size; smt().
  have hoverhead0 : 0 <= index * 112 by smt().
  have hr0 := modz_ge0 length chunk_size _; first by rewrite /chunk_size.
  have hr1 := ltz_pmod length chunk_size _; first by rewrite /chunk_size.
  have hw := record_width_positive true (length %% chunk_size) _; first by smt().
  have hd : (length %/ chunk_size) * 1114296 <= data_prefix length true.
  + by rewrite /data_prefix full_record_width /=; smt().
  by case: rs hz => /= hz; move: hz; rewrite /offset_early_zero /offset_math /=; smt().
qed.

lemma record_offset_execution_fits length count rs index :
  uint64_domain length => uint64_domain count => uint64_domain index =>
  offset_math length count rs index < uint64_modulus =>
  record_offset_execution length count rs index = (offset_math length count rs index, true).
proof.
  move=> hl hc hi hfit.
  have hp := offset_math_nonnegative length count rs index hl hi.
  have hz := offset_early_cannot_fit length count rs index hl hi.
  have hmod : offset_math length count rs index %% uint64_modulus =
      offset_math length count rs index by apply pmod_small; smt().
  rewrite (record_offset_execution_closed_form length count rs index hl hc hi) /offset_result.
  by smt().
qed.

lemma offset_math_canonical length count rs index :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  offset_math length count rs index = record_offset length rs index.
proof.
  move=> hl hc hi.
  have hindex : 0 <= index <= canonical_count length by smt().
  case: rs => /=.
  + by rewrite /offset_math hc /record_offset full_record_width.
  have ho := record_offset_nonrs length index hl hindex.
  by rewrite /offset_math hc /=; smt().
qed.

lemma offset_early_canonical length count rs index :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  offset_early_zero length count rs index =
    (rs /\ index = count /\ uint64_modulus <= (length %/ chunk_size) * 1114296).
proof.
  move=> hl hc hi.
  have hcount := canonical_count_bound length hl.
  have hoverhead : index * 112 < uint64_modulus
    by move: hcount; rewrite /reachable_count_bound /uint64_modulus; smt().
  have hplain : index < count => index * chunk_size < uint64_modulus.
  + move=> hdata.
    have hchunk := canonical_chunk_bounds length index hl _; first by smt().
    by move: hl; rewrite /uint64_domain; smt().
  by case: rs; rewrite /offset_early_zero /=; smt().
qed.

lemma offset_result_canonical length count rs index :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  offset_result length count rs index =
    (if rs /\ index = count /\ uint64_modulus <= (length %/ chunk_size) * 1114296 then 0
     else record_offset length rs index %% uint64_modulus,
     record_offset length rs index < uint64_modulus).
proof.
  by move=> hl hc hi; rewrite /offset_result (offset_math_canonical length count rs index hl hc hi)
    (offset_early_canonical length count rs index hl hc hi).
qed.

lemma offset_source_contract_canonical_flag length count rs index result ok :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  offset_source_contract length count rs index result ok =>
  ok = (record_offset length rs index < uint64_modulus).
proof.
  move=> hl hc hi hsource.
  have ho := offset_math_canonical length count rs index hl hc hi.
  have hf := offset_source_contract_fields length count rs index result ok.
  by smt().
qed.

lemma offset_source_contract_canonical_fits length count rs index result ok :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  record_offset length rs index < uint64_modulus =>
  offset_source_contract length count rs index result ok =>
  (result, ok) = (record_offset length rs index, true).
proof.
  move=> hl hc hi hfit hsource.
  have hcount := canonical_count_bound length hl.
  have hcword : uint64_domain count
    by move: hcount; rewrite /uint64_domain /uint64_modulus /reachable_count_bound; smt().
  have hiword : uint64_domain index
    by move: hcount; rewrite /uint64_domain /uint64_modulus /reachable_count_bound; smt().
  have ho := offset_math_canonical length count rs index hl hc hi.
  have he := record_offset_execution_fits length count rs index hl hcword hiword _; first by smt().
  have hm := offset_source_contract_refines_model length count rs index result ok hl hcword hiword hsource.
  by smt().
qed.

lemma offset_source_contract_payload_fit length count rs index result ok :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  payload_length length rs < uint64_modulus =>
  offset_source_contract length count rs index result ok =>
  (result, ok) = (record_offset length rs index, true).
proof.
  move=> hl hc hi hp hsource.
  have hindex : 0 <= index <= canonical_count length by smt().
  have ho := record_offset_bounds length rs index hl hindex.
  have hd : data_prefix length rs <= payload_length length rs.
  + by rewrite /payload_length final_record_width; case: rs; smt().
  apply (offset_source_contract_canonical_fits length count rs index result ok) => //.
  by smt().
qed.

lemma offset_source_contract_payload_success length count rs index result ok payload_value payload_ok :
  uint64_domain length => uint64_domain count => 0 <= index <= count =>
  payload_source_contract length count rs payload_value payload_ok => payload_ok =>
  offset_source_contract length count rs index result ok =>
  (result, ok) = (record_offset length rs index, true).
proof.
  move=> hl hc hi hpayload hpok hsource.
  have hp := payload_source_contract_success length count rs payload_value payload_ok hl hc hpayload hpok.
  have hf := payload_source_contract_fields length count rs payload_value payload_ok.
  have hcount : count = canonical_count length by move: hp; rewrite /payload_valid_count; smt().
  have hfit : payload_length length rs < uint64_modulus by smt().
  by apply (offset_source_contract_payload_fit length count rs index result ok).
qed.

lemma offset_source_contract_host_extents header length count rs index result ok :
  uint64_domain length => count = canonical_count length => 0 <= index <= count =>
  0 <= header => header + payload_length length rs <= max_int64 =>
  offset_source_contract length count rs index result ok =>
  (result, ok) = (record_offset length rs index, true) /\
  0 <= header + result <= max_int64 /\ 0 <= header + result + 48 <= max_int64 /\
  header + result + record_width rs (record_body_length length index) <= header + payload_length length rs /\
  (index = count => header + result + record_width rs (record_body_length length index) =
    header + payload_length length rs).
proof.
  move=> hl hc hi hh hb hsource.
  have hindex : 0 <= index <= canonical_count length by smt().
  have hp : payload_length length rs < uint64_modulus
    by move: hb; rewrite /max_int64 /uint64_modulus; smt().
  have hs := offset_source_contract_payload_fit length count rs index result ok hl hc hi hp hsource.
  have he := record_host_extents header length rs index hl hindex hh hb.
  by move: he; rewrite /descriptor_offset /body_offset /record_end /record_width; smt().
qed.

lemma offset_rs_data_wrap_witness :
  record_offset_execution max_uint64 reachable_count_bound true 16554617510706 = (101360, false).
proof.
  have hl : uint64_domain max_uint64 by rewrite /uint64_domain /uint64_modulus /max_uint64.
  have hc : uint64_domain reachable_count_bound
    by rewrite /uint64_domain /uint64_modulus /reachable_count_bound.
  have hi : uint64_domain 16554617510706 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form _ _ true _ hl hc hi)
    /offset_result /offset_math /offset_early_zero /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /uint64_modulus /max_uint64 /reachable_count_bound.
qed.

lemma offset_rs_partial_wrap_witness :
  record_offset_execution 17358774610905959233 16554617510706 true 16554617510706 = (40, false).
proof.
  have hl : uint64_domain 17358774610905959233 by rewrite /uint64_domain /uint64_modulus.
  have hc : uint64_domain 16554617510706 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form _ _ true _ hl hc hc)
    /offset_result /offset_math /offset_early_zero /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /uint64_modulus.
qed.

lemma offset_rs_early_zero_witness :
  record_offset_execution 17358774610906054656 16554617510706 true 16554617510706 = (0, false) /\
  offset_math 17358774610906054656 16554617510706 true 16554617510706 %% uint64_modulus = 101360.
proof.
  have hl : uint64_domain 17358774610906054656 by rewrite /uint64_domain /uint64_modulus.
  have hc : uint64_domain 16554617510706 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form _ _ true _ hl hc hc)
    /offset_result /offset_math /offset_early_zero /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /uint64_modulus.
qed.

lemma offset_nonrs_early_zero_witness :
  record_offset_execution 0 0 false 164703072086692426 = (0, false) /\
  offset_math 0 0 false 164703072086692426 %% uint64_modulus = 96.
proof.
  have hz : uint64_domain 0 by rewrite /uint64_domain /uint64_modulus.
  have hi : uint64_domain 164703072086692426 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form 0 0 false _ hz hz hi)
    /offset_result /offset_math /offset_early_zero /uint64_modulus.
qed.

lemma offset_nonrs_final_wrap_witness :
  record_offset_execution max_uint64 0 false 1 = (111, false).
proof.
  have hl : uint64_domain max_uint64 by rewrite /uint64_domain /uint64_modulus /max_uint64.
  have hz : uint64_domain 0 by rewrite /uint64_domain /uint64_modulus.
  have hi : uint64_domain 1 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form _ 0 false 1 hl hz hi)
    /offset_result /offset_math /offset_early_zero /uint64_modulus /max_uint64.
qed.

lemma offset_does_not_validate_count_or_index :
  record_offset_execution 1 0 false 0 = (1, true) /\
  record_offset_execution 1 0 true 0 = (184, true) /\
  record_offset_execution 1 1 false 2 = (225, true) /\
  record_offset_execution 1 1 true 2 = (184, true).
proof.
  have hz : uint64_domain 0 by rewrite /uint64_domain /uint64_modulus.
  have ho : uint64_domain 1 by rewrite /uint64_domain /uint64_modulus.
  have ht : uint64_domain 2 by rewrite /uint64_domain /uint64_modulus.
  by rewrite (record_offset_execution_closed_form 1 0 false 0 ho hz hz)
    (record_offset_execution_closed_form 1 0 true 0 ho hz hz)
    (record_offset_execution_closed_form 1 1 false 2 ho ho ht)
    (record_offset_execution_closed_form 1 1 true 2 ho ho ht)
    /offset_result /offset_math /offset_early_zero /data_prefix /record_width /encoded_body_length
    /semantic_body_length /ceiling /chunk_size /uint64_modulus.
qed.

(* The uint32 input embeds by value into uint64; the caller's 99999-byte limit
   is separate. The three outputs retain the source's existing named results. *)
op metadata_comment_domain (comment : int) : bool = 0 <= comment < 4294967296.

op metadata_execution (comment : int) : int * int * bool =
  let decoded = checked_add 80 comment in
  if !decoded.`2 then (0, 0, false)
  else let blocks = checked_ceil_div decoded.`1 128 in
    if !blocks.`2 then (0, 0, false)
    else let encoded = checked_mul blocks.`1 136 in
      if !encoded.`2 then (0, 0, false)
      else let header = checked_add 976 encoded.`1 in
        (blocks.`1, header.`1, header.`2).

op metadata_source_contract (comment blocks frontHeaderLength : int) (ok : bool) : bool =
  ok /\ 1 <= blocks <= 33554433 /\ 1112 <= frontHeaderLength <= 4563403864 /\
  blocks = metadata_blocks comment /\ frontHeaderLength = 976 + 136 * blocks /\
  (comment <= 99999 => blocks <= 782 /\ frontHeaderLength <= 107328).

lemma metadata_comment_embeds_uint64 comment :
  metadata_comment_domain comment => uint64_domain comment.
proof. by rewrite /metadata_comment_domain /uint64_domain /uint64_modulus; smt(). qed.

lemma metadata_full_input_bounds comment :
  metadata_comment_domain comment =>
  1 <= metadata_blocks comment <= 33554433 /\
  1112 <= header_length comment <= 4563403864.
proof.
  move=> hc.
  have hs : 0 <= 80 + comment by move: hc; rewrite /metadata_comment_domain; smt().
  have hi := ceiling_128_interval (80 + comment) hs.
  by move: hc hi; rewrite /metadata_comment_domain /metadata_blocks /header_length; smt().
qed.

lemma metadata_execution_matches_geometry comment :
  metadata_comment_domain comment =>
  metadata_execution comment = (metadata_blocks comment, header_length comment, true).
proof.
  move=> hc.
  have hcomment := metadata_comment_embeds_uint64 comment hc.
  have hb := metadata_full_input_bounds comment hc.
  have h80 : uint64_domain 80 by rewrite /uint64_domain /uint64_modulus.
  have h128 : uint64_domain 128 by rewrite /uint64_domain /uint64_modulus.
  have h136 : uint64_domain 136 by rewrite /uint64_domain /uint64_modulus.
  have h976 : uint64_domain 976 by rewrite /uint64_domain /uint64_modulus.
  have hdecoded_fit : 80 + comment < uint64_modulus
    by move: hc; rewrite /metadata_comment_domain /uint64_modulus; smt().
  have hdecoded : uint64_domain (80 + comment)
    by move: hc; rewrite /metadata_comment_domain /uint64_domain /uint64_modulus; smt().
  have hceil := checked_ceil_div_contract (80 + comment) 128 hdecoded h128 _; first by done.
  have hblocks : checked_ceil_div (80 + comment) 128 = (metadata_blocks comment, true)
    by move: hceil; rewrite /metadata_blocks; smt().
  have hblocks_word : uint64_domain (metadata_blocks comment)
    by move: hb; rewrite /uint64_domain /uint64_modulus; smt().
  have hencoded_fit : metadata_blocks comment * 136 < uint64_modulus
    by move: hb; rewrite /uint64_modulus; smt().
  have hencoded_word : uint64_domain (metadata_blocks comment * 136)
    by move: hb; rewrite /uint64_domain /uint64_modulus; smt().
  have hheader_fit : 976 + metadata_blocks comment * 136 < uint64_modulus
    by move: hb; rewrite /uint64_modulus /header_length; smt().
  rewrite /metadata_execution (add_word_fits 80 comment h80 hcomment hdecoded_fit) /=
    hblocks /= (mul_word_fits _ _ hblocks_word h136 hencoded_fit) /=
    (add_word_fits _ _ h976 hencoded_word hheader_fit) /=.
  by rewrite /header_length; smt().
qed.

lemma metadata_source_contract_fields comment blocks frontHeaderLength ok :
  metadata_source_contract comment blocks frontHeaderLength ok =
    (ok /\ 1 <= blocks <= 33554433 /\ 1112 <= frontHeaderLength <= 4563403864 /\
     blocks = (80 + comment) %/ 128 + (if (80 + comment) %% 128 = 0 then 0 else 1) /\
     frontHeaderLength = 976 + 136 * blocks /\
     (comment <= 99999 => blocks <= 782 /\ frontHeaderLength <= 107328)).
proof. by rewrite /metadata_source_contract /metadata_blocks /ceiling. qed.

lemma metadata_geometry_satisfies_source_contract comment :
  metadata_comment_domain comment =>
  metadata_source_contract comment (metadata_blocks comment) (header_length comment) true.
proof.
  move=> hc.
  have hb := metadata_full_input_bounds comment hc.
  have hcaller : comment <= 99999 =>
      metadata_blocks comment <= 782 /\ header_length comment <= 107328.
  + move=> hl.
    have hsmall := metadata_header_bounds comment _.
    + by move: hc; rewrite /metadata_comment_domain; smt().
    by smt().
  by rewrite /metadata_source_contract /header_length; smt().
qed.

lemma metadata_execution_source_contract comment :
  metadata_comment_domain comment =>
  metadata_source_contract comment (metadata_execution comment).`1
    (metadata_execution comment).`2 (metadata_execution comment).`3.
proof.
  move=> hc.
  by rewrite (metadata_execution_matches_geometry comment hc) /=;
    apply metadata_geometry_satisfies_source_contract.
qed.

lemma metadata_source_contract_refines_model comment blocks frontHeaderLength ok :
  metadata_comment_domain comment => metadata_source_contract comment blocks frontHeaderLength ok =>
  (blocks, frontHeaderLength, ok) = metadata_execution comment.
proof.
  move=> hc hsource.
  rewrite (metadata_execution_matches_geometry comment hc).
  by move: hsource; rewrite /metadata_source_contract /header_length; smt().
qed.

lemma metadata_source_contract_geometry comment blocks frontHeaderLength ok :
  metadata_source_contract comment blocks frontHeaderLength ok =>
  (blocks, frontHeaderLength, ok) = (metadata_blocks comment, header_length comment, true).
proof. by rewrite /metadata_source_contract /header_length; smt(). qed.

lemma metadata_source_contract_unique comment blocks1 header1 ok1 blocks2 header2 ok2 :
  metadata_source_contract comment blocks1 header1 ok1 =>
  metadata_source_contract comment blocks2 header2 ok2 =>
  (blocks1, header1, ok1) = (blocks2, header2, ok2).
proof. by rewrite /metadata_source_contract; smt(). qed.

lemma metadata_source_contract_uint64_outputs comment blocks frontHeaderLength ok :
  metadata_source_contract comment blocks frontHeaderLength ok =>
  uint64_domain blocks /\ uint64_domain frontHeaderLength.
proof. by rewrite /metadata_source_contract /uint64_domain /uint64_modulus; smt(). qed.

lemma metadata_source_contract_caller_limit comment blocks frontHeaderLength ok :
  metadata_comment_domain comment => comment <= 99999 =>
  metadata_source_contract comment blocks frontHeaderLength ok =>
  1 <= blocks <= 782 /\ 1112 <= frontHeaderLength <= 107328 /\ ok.
proof. by rewrite /metadata_source_contract; smt(). qed.

lemma metadata_zero_witness : metadata_execution 0 = (1, 1112, true).
proof.
  have hc : metadata_comment_domain 0 by rewrite /metadata_comment_domain.
  by rewrite (metadata_execution_matches_geometry 0 hc) /metadata_blocks /header_length /ceiling.
qed.

lemma metadata_48_witness : metadata_execution 48 = (1, 1112, true).
proof.
  have hc : metadata_comment_domain 48 by rewrite /metadata_comment_domain.
  by rewrite (metadata_execution_matches_geometry 48 hc) /metadata_blocks /header_length /ceiling.
qed.

lemma metadata_49_witness : metadata_execution 49 = (2, 1248, true).
proof.
  have hc : metadata_comment_domain 49 by rewrite /metadata_comment_domain.
  by rewrite (metadata_execution_matches_geometry 49 hc) /metadata_blocks /header_length /ceiling.
qed.

lemma metadata_99999_witness : metadata_execution 99999 = (782, 107328, true).
proof.
  have hc : metadata_comment_domain 99999 by rewrite /metadata_comment_domain.
  by rewrite (metadata_execution_matches_geometry 99999 hc) /metadata_blocks /header_length /ceiling.
qed.

lemma metadata_max_uint32_witness :
  metadata_execution 4294967295 = (33554433, 4563403864, true) /\
  4294967295 < header_length 4294967295.
proof.
  have hc : metadata_comment_domain 4294967295 by rewrite /metadata_comment_domain.
  by rewrite (metadata_execution_matches_geometry 4294967295 hc) /metadata_blocks /header_length /ceiling.
qed.

op metadata_floor_execution (comment : int) : int * int * bool =
  let decoded = checked_add 80 comment in
  if !decoded.`2 then (0, 0, false)
  else let blocks = checked_add (decoded.`1 %/ 128) 0 in
    if !blocks.`2 then (0, 0, false)
    else let encoded = checked_mul blocks.`1 136 in
      if !encoded.`2 then (0, 0, false)
      else let header = checked_add 976 encoded.`1 in
        (blocks.`1, header.`1, header.`2).

lemma metadata_floor_counterexample :
  metadata_floor_execution 0 = (0, 976, true) /\
  metadata_execution 0 = (1, 1112, true) /\
  !metadata_source_contract 0 0 976 true.
proof.
  by rewrite metadata_zero_witness /metadata_floor_execution /checked_add /add_parts
    /checked_ceil_div /checked_mul /mul_parts /metadata_source_contract /uint64_modulus.
qed.
