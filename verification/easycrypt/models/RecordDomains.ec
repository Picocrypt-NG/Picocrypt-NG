require import AllCore IntDiv List RecordFraming BigEndianFields CanonicalRecords.
require SafeCastRepresentation.

(* Parameter models; source, keys, prefix generation and cipher semantics are
   separate interfaces. This model does not use Gobra's shift encoding. *)
op word64_modulus : int = 18446744073709551616.
op counter128_modulus : int = word64_modulus * word64_modulus.
op serpent_stride : int = 65536.
op valid_record_index (index : int) : bool = 0 <= index < maximum_record_count.

op go_u64_shift16 (index : int) : int =
  (index * serpent_stride) %% word64_modulus.
(* Signed interpretation of those bits; the production index is uint64. *)
op go_i64_shift16 (index : int) : int =
  SafeCastRepresentation.go_signed (go_u64_shift16 index).

op record_nonce (prefix : bytes) (index : int) : bytes = prefix ++ be64 index.
op serpent_iv (prefix : bytes) (index : int) : bytes =
  prefix ++ be64 (go_u64_shift16 index).

op blocks_for (block_bytes length : int) : int =
  if length = 0 then 0 else (length - 1) %/ block_bytes + 1.
op serpent_blocks (length : int) : int = blocks_for 16 length.
op xchacha_blocks (length : int) : int = blocks_for 64 length.

(* Full 128-bit big-endian increment for consumed blocks; buffered unused
   keystream and post-refill counter state are outside this model. *)
op ctr_counter (prefix : bytes) (index block : int) : int =
  (from_be (serpent_iv prefix index) + block) %% counter128_modulus.
op serpent_uses (prefix : bytes) (index length counter : int) : bool =
  exists block, 0 <= block < serpent_blocks length /\
    counter = ctr_counter prefix index block.

lemma word64_power : 2^64 = word64_modulus.
proof. by rewrite /word64_modulus; ring. qed.

lemma counter128_power : 2^128 = counter128_modulus.
proof. by rewrite /counter128_modulus /word64_modulus; ring. qed.

lemma prefix8_range (prefix : bytes) :
  size prefix = 8 => 0 <= from_be prefix < word64_modulus.
proof.
  move=> hp.
  have h := from_be_range prefix.
  by move: h; rewrite hp /= word64_power.
qed.

lemma go_u64_shift16_range index :
  0 <= go_u64_shift16 index < word64_modulus.
proof.
  have hlo := modz_ge0 (index * serpent_stride) word64_modulus _.
  + by rewrite /word64_modulus.
  have hhi := ltz_pmod (index * serpent_stride) word64_modulus _.
  + by rewrite /word64_modulus.
  by rewrite /go_u64_shift16; smt().
qed.

lemma go_i64_shift16_range index :
  SafeCastRepresentation.int64_domain (go_i64_shift16 index).
proof.
  apply SafeCastRepresentation.go_signed_result_range.
  have h := go_u64_shift16_range index.
  by move: h; rewrite /SafeCastRepresentation.uint64_domain
    /SafeCastRepresentation.uint64_modulus /word64_modulus.
qed.

lemma go_u64_shift16_small index :
  valid_record_index index => go_u64_shift16 index = index * serpent_stride.
proof.
  move=> hi; rewrite /go_u64_shift16; apply pmod_small.
  by move: hi; rewrite /valid_record_index /maximum_record_count
    /serpent_stride /word64_modulus; smt().
qed.

lemma shift16_first_wrap : go_u64_shift16 maximum_record_count = 0.
proof.
  by rewrite /go_u64_shift16 /maximum_record_count /serpent_stride
    /word64_modulus /=.
qed.

lemma shift16_signed_view_at_half_limit :
  go_i64_shift16 140737488355328 = SafeCastRepresentation.min_int64.
proof.
  have hi : valid_record_index 140737488355328
    by rewrite /valid_record_index /maximum_record_count.
  by rewrite /go_i64_shift16 (go_u64_shift16_small _ hi)
    /serpent_stride /SafeCastRepresentation.go_signed
    /SafeCastRepresentation.max_int64 /SafeCastRepresentation.uint64_modulus
    /SafeCastRepresentation.min_int64.
qed.

lemma record_nonce_size prefix index :
  size prefix = 16 => size (record_nonce prefix index) = 24.
proof. by rewrite /record_nonce size_cat size_be64 => ->. qed.

lemma record_nonce_injective prefix index1 index2 :
  SafeCastRepresentation.uint64_domain index1 =>
  SafeCastRepresentation.uint64_domain index2 =>
  record_nonce prefix index1 = record_nonce prefix index2 => index1 = index2.
proof.
  move=> hf hs he.
  have h := congr1 (fun b : bytes => drop (size prefix) b) _ _ he.
  have hencoding : be64 index1 = be64 index2.
  + by move: h; rewrite /= /record_nonce !drop_size_cat.
  by apply (be64_injective index1 index2) => //.
qed.

lemma record_nonce_distinct prefix index1 index2 :
  valid_record_index index1 => valid_record_index index2 => index1 <> index2 =>
  record_nonce prefix index1 <> record_nonce prefix index2.
proof.
  move=> hf hs hd.
  have hu : SafeCastRepresentation.uint64_domain index1 /\
      SafeCastRepresentation.uint64_domain index2.
  + by move: hf hs; rewrite /valid_record_index /maximum_record_count
      /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus;
      smt().
  by smt(record_nonce_injective).
qed.

lemma serpent_iv_size prefix index :
  size prefix = 8 => size (serpent_iv prefix index) = 16.
proof. by rewrite /serpent_iv size_cat size_be64 => ->. qed.

lemma serpent_iv_value prefix index :
  from_be (serpent_iv prefix index) =
    from_be prefix * word64_modulus + go_u64_shift16 index.
proof.
  have hs : 0 <= go_u64_shift16 index < 18446744073709551616.
  + have h := go_u64_shift16_range index.
    by move: h; rewrite /word64_modulus.
  by rewrite /serpent_iv from_be_cat size_be64 /= word64_power
    (from_be64K _ hs); ring.
qed.

lemma serpent_blocks_bounds length :
  0 <= length <= chunk_size => 0 <= serpent_blocks length <= serpent_stride.
proof.
  move=> hl.
  case (length = 0) => hz.
  + by rewrite hz /serpent_blocks /blocks_for /serpent_stride.
  have hq : 0 <= (length - 1) %/ 16 by apply divz_ge0; smt().
  have hr := modz_ge0 (length - 1) 16 _; first by done.
  have hd := divz_eq (length - 1) 16.
  by rewrite /serpent_blocks /blocks_for hz;
    move: hl hq hr hd; rewrite /chunk_size /serpent_stride; smt().
qed.

lemma xchacha_blocks_bounds length :
  0 <= length <= chunk_size => 0 <= xchacha_blocks length <= 16384 /\
    xchacha_blocks length < 4294967296.
proof.
  move=> hl.
  case (length = 0) => hz.
  + by rewrite hz /xchacha_blocks /blocks_for.
  have hq : 0 <= (length - 1) %/ 64 by apply divz_ge0; smt().
  have hr := modz_ge0 (length - 1) 64 _; first by done.
  have hd := divz_eq (length - 1) 64.
  by rewrite /xchacha_blocks /blocks_for hz;
    move: hl hq hr hd; rewrite /chunk_size; smt().
qed.

lemma full_record_blocks :
  serpent_blocks chunk_size = serpent_stride /\ xchacha_blocks chunk_size = 16384.
proof. by rewrite /serpent_blocks /xchacha_blocks /blocks_for /chunk_size /serpent_stride. qed.

lemma one_byte_record_blocks : serpent_blocks 1 = 1 /\ xchacha_blocks 1 = 1.
proof. by rewrite /serpent_blocks /xchacha_blocks /blocks_for. qed.

lemma used_low_counter_bounds index block :
  valid_record_index index => 0 <= block < serpent_stride =>
  0 <= index * serpent_stride + block < word64_modulus.
proof.
  by rewrite /valid_record_index /maximum_record_count /serpent_stride
    /word64_modulus; smt().
qed.

lemma ctr_used_counter_value prefix index block :
  size prefix = 8 => valid_record_index index => 0 <= block < serpent_stride =>
  ctr_counter prefix index block =
    from_be prefix * word64_modulus + index * serpent_stride + block.
proof.
  move=> hp hi hb.
  have hprefix := prefix8_range prefix hp.
  have hlow := used_low_counter_bounds index block hi hb.
  rewrite /ctr_counter serpent_iv_value (go_u64_shift16_small _ hi).
  apply pmod_small.
  by move: hprefix hlow; rewrite /word64_modulus /counter128_modulus; smt().
qed.

lemma used_counter_preserves_prefix prefix index block :
  size prefix = 8 => valid_record_index index => 0 <= block < serpent_stride =>
  be 16 (ctr_counter prefix index block) =
    prefix ++ be64 (index * serpent_stride + block).
proof.
  move=> hp hi hb.
  have hlow := used_low_counter_bounds index block hi hb.
  have hr : 0 <= index * serpent_stride + block < 18446744073709551616
    by move: hlow; rewrite /word64_modulus.
  have h := be_from_beK (prefix ++ be64 (index * serpent_stride + block)).
  rewrite size_cat hp size_be64 /= from_be_cat size_be64 /= word64_power
    (from_be64K _ hr) in h.
  by rewrite (ctr_used_counter_value prefix index block hp hi hb); smt().
qed.

lemma distinct_records_use_distinct_counters prefix index1 index2 first_block second_block :
  size prefix = 8 => valid_record_index index1 => valid_record_index index2 =>
  0 <= first_block < serpent_stride => 0 <= second_block < serpent_stride =>
  index1 <> index2 =>
  ctr_counter prefix index1 first_block <> ctr_counter prefix index2 second_block.
proof.
  move=> hp hf hs hfb hsb hd.
  rewrite (ctr_used_counter_value prefix index1 first_block hp hf hfb)
    (ctr_used_counter_value prefix index2 second_block hp hs hsb).
  by move: hfb hsb hd; rewrite /serpent_stride; smt().
qed.

lemma record_used_intervals_disjoint prefix index1 index2 first_length second_length counter :
  size prefix = 8 => valid_record_index index1 => valid_record_index index2 =>
  0 <= first_length <= chunk_size => 0 <= second_length <= chunk_size => index1 <> index2 =>
  !(serpent_uses prefix index1 first_length counter /\
    serpent_uses prefix index2 second_length counter).
proof.
  move=> hp hf hs hfl hsl hd.
  have hbf := serpent_blocks_bounds first_length hfl.
  have hbs := serpent_blocks_bounds second_length hsl.
  rewrite /serpent_uses.
  by smt(distinct_records_use_distinct_counters).
qed.

(* Normal PCV3 has an empty final record; D1 outer finals may contain data. *)
op normal_record_length (length index : int) : int =
  if index = canonical_count length then 0 else chunk_length length index.

lemma normal_record_parameters length index :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  canonical_count length <= reachable_count_bound /\ valid_record_index index /\
  0 <= normal_record_length length index <= chunk_size.
proof.
  move=> hl hi.
  have hc := canonical_count_bound length hl.
  have hr := reachable_final_index length index hl hi.
  rewrite /normal_record_length /valid_record_index.
  case (index = canonical_count length) => hf.
  + by move: hc hr; rewrite /chunk_size; smt().
  have hb := canonical_chunk_bounds length index hl _; first by smt().
  by smt().
qed.

lemma normal_final_uses_no_counter prefix length counter :
  !serpent_uses prefix (canonical_count length)
    (normal_record_length length (canonical_count length)) counter /\
  xchacha_blocks (normal_record_length length (canonical_count length)) = 0.
proof.
  by rewrite /normal_record_length /serpent_uses /serpent_blocks /xchacha_blocks /blocks_for;
    smt().
qed.

lemma normal_xchacha_capacity length index :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  0 <= xchacha_blocks (normal_record_length length index) <= 16384 /\
  xchacha_blocks (normal_record_length length index) < 4294967296.
proof.
  move=> hl hi.
  have h := normal_record_parameters length index hl hi.
  by apply xchacha_blocks_bounds; smt().
qed.

lemma normal_used_intervals_disjoint prefix length index1 index2 counter :
  size prefix = 8 => SafeCastRepresentation.uint64_domain length =>
  0 <= index1 <= canonical_count length => 0 <= index2 <= canonical_count length =>
  index1 <> index2 =>
  !(serpent_uses prefix index1 (normal_record_length length index1) counter /\
    serpent_uses prefix index2 (normal_record_length length index2) counter).
proof.
  move=> hp hl hi1 hi2 hd.
  have h1 := normal_record_parameters length index1 hl hi1.
  have h2 := normal_record_parameters length index2 hl hi2.
  by apply record_used_intervals_disjoint; smt().
qed.

lemma normal_data_low_counter_bound length index block :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index < canonical_count length => 0 <= block < serpent_stride =>
  0 <= index * serpent_stride + block < 1152921504606846976.
proof.
  move=> hl hi hb.
  have hc := canonical_count_bound length hl.
  by move: hc hi hb; rewrite /reachable_count_bound /serpent_stride; smt().
qed.

(* At the generic limit, the unused next counter may carry into the prefix.
   This witness deliberately does not assert anything about buffered post-state. *)
lemma last_generic_used_counter prefix :
  size prefix = 8 =>
  ctr_counter prefix (maximum_record_count - 1) (serpent_stride - 1) =
    (from_be prefix + 1) * word64_modulus - 1.
proof.
  move=> hp.
  have hi : valid_record_index (maximum_record_count - 1)
    by rewrite /valid_record_index /maximum_record_count.
  have hb : 0 <= serpent_stride - 1 < serpent_stride by rewrite /serpent_stride.
  by rewrite (ctr_used_counter_value _ _ _ hp hi hb)
    /maximum_record_count /serpent_stride /word64_modulus; ring.
qed.

lemma next_after_generic_limit_carries prefix :
  size prefix = 8 =>
  (ctr_counter prefix (maximum_record_count - 1) (serpent_stride - 1) + 1)
    %% counter128_modulus =
  ((from_be prefix + 1) * word64_modulus) %% counter128_modulus.
proof. by move=> hp; rewrite (last_generic_used_counter _ hp) subrK. qed.

op ctr_shift15 (prefix : bytes) (index block : int) : int =
  (from_be prefix * word64_modulus + (index * 32768) %% word64_modulus + block)
    %% counter128_modulus.

lemma shift15_full_record_overlap :
  0 <= 32768 < serpent_blocks chunk_size /\
  0 <= 0 < serpent_blocks chunk_size /\
  ctr_shift15 (nseq 8 (byte_of_int 0)) 0 32768 =
    ctr_shift15 (nseq 8 (byte_of_int 0)) 1 0.
proof.
  rewrite /ctr_shift15 from_be_zero /serpent_blocks /blocks_for
    /chunk_size /word64_modulus /counter128_modulus /=.
  by smt().
qed.

op nonce_truncated32 (prefix : bytes) (index : int) : bytes =
  prefix ++ (nseq 4 (byte_of_int 0) ++ be32 index).

lemma truncated32_nonce_alias prefix :
  nonce_truncated32 prefix 0 = nonce_truncated32 prefix 4294967296.
proof. by rewrite /nonce_truncated32 be32_truncation_alias. qed.

lemma truncated32_keeps_nonce_shape prefix :
  size prefix = 16 => size (nonce_truncated32 prefix 4294967296) = 24.
proof. by rewrite /nonce_truncated32 !size_cat size_nseq size_be32 => ->. qed.

lemma truncated32_alias_has_distinct_correct_nonces prefix :
  record_nonce prefix 0 <> record_nonce prefix 4294967296.
proof.
  apply record_nonce_distinct;
    by rewrite /valid_record_index /maximum_record_count.
qed.

lemma truncation_witness_has_two_data_records :
  SafeCastRepresentation.uint64_domain 4503599628419072 /\
  canonical_count 4503599628419072 = 4294967297 /\
  0 <= 0 < canonical_count 4503599628419072 /\
  0 <= 4294967296 < canonical_count 4503599628419072.
proof.
  by rewrite /SafeCastRepresentation.uint64_domain /SafeCastRepresentation.uint64_modulus
    /canonical_count /chunk_size.
qed.

lemma prefix_octet_contract_determines_encoding (prefix encoded : bytes) value :
  size encoded = size prefix + 8 =>
  (forall position, 0 <= position < size prefix =>
    nth (byte_of_int 0) encoded position = nth (byte_of_int 0) prefix position) =>
  (forall position, 0 <= position < 8 =>
    from_be [nth (byte_of_int 0) encoded (size prefix + position)] = octet64 value position) =>
  encoded = prefix ++ be64 value.
proof.
  move=> hs hprefix hoctets.
  have htake : take (size prefix) encoded = prefix.
  + apply (eq_from_nth (byte_of_int 0)).
    + by rewrite size_take ?size_ge0 hs; smt(size_ge0).
    move=> position hi.
    have hr : 0 <= position < size prefix.
    + by move: hi; rewrite size_take ?size_ge0 hs; smt(size_ge0).
    rewrite nth_take ?size_ge0 1:/#.
    exact (hprefix position hr).
  have htail_size : size (drop (size prefix) encoded) = 8.
  + by rewrite size_drop ?size_ge0 hs; smt().
  have htail : drop (size prefix) encoded = be64 value.
  + apply (octet64_contract_determines_be64 _ value htail_size).
    move=> position hi.
    by rewrite nth_drop ?size_ge0 1:/#; exact (hoctets position hi).
  by rewrite -(cat_take_drop (size prefix) encoded) htake htail.
qed.

(* Value postconditions are premises. Receiver permissions, old-value snapshots
   and Go-byte embeddings belong to the separate source correspondence. *)
op parameter_frame_contract
    (x_prefix serpent_prefix nonce_out iv_out : bytes) (index shifted : int) : bool =
  size x_prefix = 16 /\ size serpent_prefix = 8 /\
  size nonce_out = 24 /\ size iv_out = 16 /\
  (forall position, 0 <= position < 16 =>
    nth (byte_of_int 0) nonce_out position = nth (byte_of_int 0) x_prefix position) /\
  (forall position, 0 <= position < 8 =>
    nth (byte_of_int 0) iv_out position = nth (byte_of_int 0) serpent_prefix position) /\
  (forall position, 0 <= position < 8 =>
    from_be [nth (byte_of_int 0) nonce_out (16 + position)] = octet64 index position) /\
  (forall position, 0 <= position < 8 =>
    from_be [nth (byte_of_int 0) iv_out (8 + position)] = octet64 shifted position).

lemma parameter_frame_contract_determines_parameters
    (x_prefix serpent_prefix nonce_out iv_out : bytes) (index shifted : int) :
  parameter_frame_contract x_prefix serpent_prefix nonce_out iv_out index shifted =>
  nonce_out = record_nonce x_prefix index /\ iv_out = serpent_prefix ++ be64 shifted.
proof.
  rewrite /parameter_frame_contract.
  move=> [hx [hs [hn [hi [hxp [hsp [hxn hsn]]]]]]].
  have hnonce := prefix_octet_contract_determines_encoding x_prefix nonce_out index _ _ _.
  + by smt().
  + by rewrite hx.
  + by rewrite hx.
  have hiv := prefix_octet_contract_determines_encoding serpent_prefix iv_out shifted _ _ _.
  + by smt().
  + by rewrite hs.
  + by rewrite hs.
  by rewrite /record_nonce; smt().
qed.

lemma parameter_frame_contract_refines_record_parameters
    (x_prefix serpent_prefix nonce_out iv_out : bytes) (index : int) :
  parameter_frame_contract x_prefix serpent_prefix nonce_out iv_out
    index (go_u64_shift16 index) =>
  nonce_out = record_nonce x_prefix index /\ iv_out = serpent_iv serpent_prefix index.
proof.
  move=> hc.
  have h := parameter_frame_contract_determines_parameters
    x_prefix serpent_prefix nonce_out iv_out index (go_u64_shift16 index) hc.
  by rewrite /serpent_iv.
qed.
