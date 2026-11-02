require import AllCore IntDiv List BitEncoding RecordFraming.
import BS2Int BitChunking.

(* BitEncoding numbers bits from the least significant bit. Reverse byte
   chunks, preserving each byte's bit order, to obtain Go's big-endian order. *)
op be (width value : int) : bytes =
  rev (map Byte.mkword (chunk 8 (int2bs (8 * width) value))).
op from_be (encoded : bytes) : int =
  bs2int (flatten (map Byte.ofword (rev encoded))).
op be32 (value : int) : bytes = be 4 value.
op be64 (value : int) : bytes = be 8 value.

lemma byte_chunksK (bits : bool list) :
  map Byte.ofword (map Byte.mkword (chunk 8 bits)) = chunk 8 bits.
proof.
  rewrite -map_comp -{2}(@map_id (chunk 8 bits)).
  apply/eq_in_map=> b hb.
  rewrite /(\o) /idfun Byte.ofwordK //.
  exact (in_chunk_size 8 bits b _ hb).
qed.

lemma size_be (width value : int) :
  0 <= width => size (be width value) = width.
proof.
  move=> hw.
  rewrite /be size_rev size_map size_chunk // size_int2bs.
  rewrite (_ : max 0 (8 * width) = 8 * width) 1:/#.
  by rewrite mulrC mulzK.
qed.

lemma from_beK (width value : int) :
  0 <= width => 0 <= value < 2^(8 * width) =>
  from_be (be width value) = value.
proof.
  move=> hw hv.
  have hs : size (int2bs (8 * width) value) = 8 * width
    by rewrite size_int2bs; smt().
  have hd : 8 %| size (int2bs (8 * width) value).
  + apply/dvdzP; exists width; rewrite hs; ring.
  rewrite /from_be /be revK byte_chunksK chunkK //.
  by apply int2bsK; smt().
qed.

lemma byte_wordsK (encoded : bytes) :
  map Byte.mkword (map Byte.ofword encoded) = encoded.
proof.
  rewrite -map_comp; apply id_map=> b.
  by rewrite /(\o) Byte.mkwordK.
qed.

lemma byte_bits_size (encoded : bytes) :
  size (flatten (map Byte.ofword encoded)) = 8 * size encoded.
proof.
  have hw : forall b, b \in map Byte.ofword encoded => size b = 8.
  + move=> b /mapP [w [_ ->]]; exact Byte.size_word.
  by rewrite (size_flatten_ctt 8 (map Byte.ofword encoded) hw) size_map.
qed.

lemma be_from_beK (encoded : bytes) :
  be (size encoded) (from_be encoded) = encoded.
proof.
  have hw : forall b, b \in map Byte.ofword (rev encoded) => size b = 8.
  + move=> b /mapP [w [_ ->]]; exact Byte.size_word.
  have hs : size (flatten (map Byte.ofword (rev encoded))) = 8 * size encoded
    by rewrite byte_bits_size size_rev.
  by rewrite /be /from_be -hs bs2intK flattenK // byte_wordsK revK.
qed.

lemma from_be_range (encoded : bytes) :
  0 <= from_be encoded < 2^(8 * size encoded).
proof.
  have h := bs2int_le2Xs (flatten (map Byte.ofword (rev encoded))).
  move: h; rewrite byte_bits_size size_rev.
  by rewrite /from_be; smt(bs2int_ge0).
qed.

lemma size_be32 value : size (be32 value) = 4.
proof. by rewrite /be32 size_be. qed.

lemma size_be64 value : size (be64 value) = 8.
proof. by rewrite /be64 size_be. qed.

lemma from_be32K value :
  0 <= value < 4294967296 => from_be (be32 value) = value.
proof.
  move=> hv; rewrite /be32; apply from_beK => //.
  have hp : 2^32 = 4294967296 by ring.
  by rewrite /= hp.
qed.

lemma from_be64K value :
  0 <= value < 18446744073709551616 => from_be (be64 value) = value.
proof.
  move=> hv; rewrite /be64; apply from_beK => //.
  have hp : 2^64 = 18446744073709551616 by ring.
  by rewrite /= hp.
qed.

lemma be32_injective x y :
  0 <= x < 4294967296 => 0 <= y < 4294967296 =>
  be32 x = be32 y => x = y.
proof.
  move=> hx hy he.
  have h := congr1 from_be _ _ he.
  by move: h; rewrite !from_be32K.
qed.

lemma be64_injective x y :
  0 <= x < 18446744073709551616 => 0 <= y < 18446744073709551616 =>
  be64 x = be64 y => x = y.
proof.
  move=> hx hy he.
  have h := congr1 from_be _ _ he.
  by move: h; rewrite !from_be64K.
qed.

lemma from_be_cat (high low : bytes) :
  from_be (high ++ low) =
  from_be low + 2^(8 * size low) * from_be high.
proof.
  by rewrite /from_be rev_cat map_cat flatten_cat bs2int_cat
    byte_bits_size size_rev.
qed.

lemma from_be_byte value :
  0 <= value < 256 => from_be [byte_of_int value] = value.
proof.
  move=> hv.
  rewrite /from_be /= rev_cons rev_nil /= flatten_cons flatten_nil cats0
    /byte_of_int Byte.ofwordK ?size_int2bs //.
  apply int2bsK => //.
  have hp : 2^8 = 256 by ring.
  by rewrite hp.
qed.

lemma from_be_zero width :
  from_be (nseq width (byte_of_int 0)) = 0.
proof.
  elim/natind: width=> [width hw|width hw ih].
  + by rewrite nseq0_le // /from_be rev_nil /= flatten_nil bs2int_nil.
  by rewrite nseqSr // -cats1 from_be_cat from_be_byte // ih /=.
qed.

lemma be_zero width :
  0 <= width => be width 0 = nseq width (byte_of_int 0).
proof.
  move=> hw.
  have h := be_from_beK (nseq width (byte_of_int 0)).
  by move: h; rewrite size_nseq (_ : max 0 width = width) 1:/# from_be_zero.
qed.

lemma be64_zero : be64 0 = index_zero.
proof. by rewrite /be64 /index_zero be_zero. qed.

lemma be64_one : be64 1 = index_one.
proof.
  have h := be_from_beK index_one.
  have hs : size index_one = 8 by rewrite /index_one size_cat size_nseq /=.
  have hv : from_be index_one = 1.
  + by rewrite /index_one from_be_cat from_be_byte // from_be_zero /=.
  by move: h; rewrite hs hv /be64.
qed.

op descriptor_tail (length : int) (is_final : bool) : bytes =
  be32 length ++
  [if is_final then byte_of_int 1 else byte_of_int 0;
   byte_of_int 0; byte_of_int 0; byte_of_int 0].

lemma size_descriptor_tail length is_final :
  size (descriptor_tail length is_final) = 8.
proof. by rewrite /descriptor_tail size_cat size_be32 /=. qed.

lemma descriptor_tail_length_bytes length is_final :
  take 4 (descriptor_tail length is_final) = be32 length.
proof. by rewrite /descriptor_tail take_size_cat 1:size_be32. qed.

lemma descriptor_tail_length length is_final :
  0 <= length < 4294967296 =>
  from_be (take 4 (descriptor_tail length is_final)) = length.
proof. by rewrite descriptor_tail_length_bytes; apply from_be32K. qed.

lemma descriptor_tail_reserved length is_final :
  drop 5 (descriptor_tail length is_final) =
  [byte_of_int 0; byte_of_int 0; byte_of_int 0].
proof. by rewrite /descriptor_tail drop_cat size_be32 /=. qed.

lemma descriptor_tail_flag length is_final :
  nth (byte_of_int 0) (descriptor_tail length is_final) 4 =
  if is_final then byte_of_int 1 else byte_of_int 0.
proof. by rewrite /descriptor_tail nth_cat size_be32 /=. qed.

lemma descriptor_tail_final_zero :
  descriptor_tail 0 true =
  [byte_of_int 0; byte_of_int 0; byte_of_int 0; byte_of_int 0;
   byte_of_int 1; byte_of_int 0; byte_of_int 0; byte_of_int 0].
proof.
  rewrite /descriptor_tail /be32 be_zero //.
  by rewrite (nseqS 3) // (nseqS 2) // (nseqS 1) // nseq1.
qed.

lemma descriptor_tail_injective first_length second_length first_final second_final :
  0 <= first_length < 4294967296 => 0 <= second_length < 4294967296 =>
  descriptor_tail first_length first_final = descriptor_tail second_length second_final =>
  first_length = second_length /\ first_final = second_final.
proof.
  move=> hfirst hsecond he.
  have hl := congr1 (take 4) _ _ he.
  rewrite !descriptor_tail_length_bytes in hl.
  have hlen := be32_injective first_length second_length hfirst hsecond hl.
  have hf := congr1 (fun b : bytes => nth (byte_of_int 0) b 4) _ _ he.
  rewrite /= !descriptor_tail_flag in hf.
  by case: first_final; case: second_final; smt(byte_zero_one).
qed.

lemma be_mod width value :
  be width (value %% 2^(8 * width)) = be width value.
proof. by rewrite /be int2bs_mod. qed.

lemma be32_truncation_alias : be32 4294967296 = be32 0.
proof.
  have hp : 2^32 = 4294967296 by ring.
  have h := be_mod 4 4294967296.
  move: h; rewrite /= hp modzz /be32.
  by smt().
qed.

lemma be64_one_not_reversed : be64 1 <> rev (be64 1).
proof.
  rewrite be64_one /index_one.
  apply/negP=> he.
  have h := congr1 (fun b : bytes => nth (byte_of_int 0) b 0) _ _ he.
  move: h.
  rewrite rev_cat rev_cons rev_nil rev_nseq /= nth_cat size_nseq /= nth_nseq //.
  exact byte_zero_one.
qed.

lemma from_be_singleton (value : byte) :
  from_be [value] = bs2int (Byte.ofword value).
proof.
  by rewrite /from_be rev_cons rev_nil /= flatten_cons flatten_nil cats0.
qed.

lemma from_be_nth (encoded : bytes) position :
  0 <= position < size encoded =>
  from_be [nth (byte_of_int 0) encoded position] =
    (from_be encoded %/ 2^(8 * (size encoded - 1 - position))) %% 256.
proof.
  move=> hi.
  pose offset := size encoded - 1 - position.
  pose bits := flatten (map Byte.ofword (rev encoded)).
  have hoffset : 0 <= offset < size encoded by rewrite /offset; smt().
  have hrev : 0 <= offset < size (rev encoded) by rewrite size_rev.
  have hw : forall b, b \in map Byte.ofword (rev encoded) => size b = 8.
  + move=> b /mapP [w [_ ->]]; exact Byte.size_word.
  have hchunks : chunk 8 bits = map Byte.ofword (rev encoded)
    by rewrite /bits flattenK.
  have hsize : size bits = 8 * size encoded
    by rewrite /bits byte_bits_size size_rev.
  have hcount : size bits %/ 8 = size encoded
    by rewrite hsize (mulrC 8 _) mulzK.
  have hn : nth [] (chunk 8 bits) offset = take 8 (drop (8 * offset) bits).
  + by rewrite /chunk nth_mkseq //; rewrite hcount.
  have hposition : size encoded - (offset + 1) = position by rewrite /offset; ring.
  have hm : nth [] (map Byte.ofword (rev encoded)) offset =
      Byte.ofword (nth (byte_of_int 0) encoded position).
  + by rewrite (nth_map (byte_of_int 0) [] Byte.ofword offset (rev encoded) hrev)
      (nth_rev (byte_of_int 0) offset encoded hoffset) hposition.
  have hword : take 8 (drop (8 * offset) bits) =
      Byte.ofword (nth (byte_of_int 0) encoded position)
    by rewrite -hn hchunks hm.
  have hp : 2^8 = 256 by ring.
  rewrite from_be_singleton -hword -(bs2int_mod (drop (8 * offset) bits) 8 _) //.
  rewrite -(bs2int_div (8 * offset) bits _) 1:/# hp.
  by rewrite /offset /bits /from_be.
qed.

op be64_modulus : int = 18446744073709551616.
op go_remainder64 (value : int) : int =
  if value < 0 then -((-value) %% be64_modulus) else value %% be64_modulus.
op normalize64 (value : int) : int =
  go_remainder64 (go_remainder64 value + be64_modulus).

lemma go_remainder64_bounds value :
  -be64_modulus < go_remainder64 value < be64_modulus.
proof.
  have hp : 0 < be64_modulus by rewrite /be64_modulus.
  have hv0 := modz_ge0 value be64_modulus _; first by smt().
  have hv1 := ltz_pmod value be64_modulus _; first by smt().
  have hn0 := modz_ge0 (-value) be64_modulus _; first by smt().
  have hn1 := ltz_pmod (-value) be64_modulus _; first by smt().
  by rewrite /go_remainder64; smt().
qed.

lemma normalize64_mod value : normalize64 value = value %% be64_modulus.
proof.
  have hr := go_remainder64_bounds value.
  have hp : 0 < be64_modulus by rewrite /be64_modulus.
  have hsum : !(go_remainder64 value + be64_modulus < 0) by smt().
  rewrite /normalize64 {1}/go_remainder64 hsum /= modzDr.
  rewrite /go_remainder64.
  case (value < 0) => hv /=.
  + by rewrite modzNm opprK.
  by rewrite modz_mod.
qed.

lemma be64_mod value : be64 (value %% be64_modulus) = be64 value.
proof.
  have hp : 2^64 = be64_modulus by rewrite /be64_modulus; ring.
  have h := be_mod 8 value.
  by move: h; rewrite /= hp /be64.
qed.

lemma from_be64_mod value : from_be (be64 value) = value %% be64_modulus.
proof.
  have hv0 := modz_ge0 value be64_modulus _; first by rewrite /be64_modulus.
  have hv1 := ltz_pmod value be64_modulus _; first by rewrite /be64_modulus.
  rewrite -(be64_mod value); apply from_be64K.
  by move: hv0 hv1; rewrite /be64_modulus.
qed.

op be64_divisor (position : int) : int =
  if position = 0 then 72057594037927936 else
  if position = 1 then 281474976710656 else
  if position = 2 then 1099511627776 else
  if position = 3 then 4294967296 else
  if position = 4 then 16777216 else
  if position = 5 then 65536 else
  if position = 6 then 256 else 1.
op octet64 (value position : int) : int =
  (normalize64 value %/ be64_divisor position) %% 256.

lemma be64_divisor_power position :
  0 <= position < 8 => be64_divisor position = 2^(8 * (7 - position)).
proof.
  move=> hi.
  have hc : position = 0 \/ position = 1 \/ position = 2 \/ position = 3 \/
    position = 4 \/ position = 5 \/ position = 6 \/ position = 7 by smt().
  by case: hc=> [->|[->|[->|[->|[->|[->|[->|->]]]]]]];
    rewrite /be64_divisor /=; ring.
qed.

lemma be64_octet value position :
  0 <= position < 8 =>
  from_be [nth (byte_of_int 0) (be64 value) position] = octet64 value position.
proof.
  move=> hi.
  rewrite from_be_nth 1:size_be64 // size_be64 from_be64_mod
    /octet64 normalize64_mod (be64_divisor_power position hi).
  by done.
qed.

lemma byte_numeric_injective (left_byte right_byte : byte) :
  from_be [left_byte] = from_be [right_byte] => left_byte = right_byte.
proof.
  move=> he.
  have hfirst := be_from_beK [left_byte].
  have hsecond := be_from_beK [right_byte].
  have h := congr1 (be 1) _ _ he.
  by move: hfirst hsecond h; rewrite /=; smt().
qed.

lemma octet64_contract_determines_be64 (encoded : bytes) value :
  size encoded = 8 =>
  (forall position, 0 <= position < 8 =>
    from_be [nth (byte_of_int 0) encoded position] = octet64 value position) =>
  encoded = be64 value.
proof.
  move=> hs hc.
  apply (eq_from_nth (byte_of_int 0)).
  + by rewrite hs size_be64.
  move=> position hi.
  have hr : 0 <= position < 8 by smt().
  have hleft := hc position hr.
  have hright := be64_octet value position hr.
  apply byte_numeric_injective; smt().
qed.

lemma be32_low_octet64 value position :
  0 <= value < 4294967296 =>
  0 <= position < 4 =>
  from_be [nth (byte_of_int 0) (be32 value) position] =
    octet64 value (position + 4).
proof.
  move=> hv hi.
  have hr : 0 <= position + 4 < 8 by smt().
  have hnormal : normalize64 value = value.
  + rewrite normalize64_mod; apply pmod_small.
    by move: hv; rewrite /be64_modulus; smt().
  rewrite from_be_nth 1:size_be32 // size_be32 (from_be32K value hv)
    /octet64 hnormal (be64_divisor_power (position + 4) hr).
  by rewrite (_ : 7 - (position + 4) = 3 - position) 1:/#.
qed.

lemma low_octet64_contract_determines_be32 (encoded : bytes) value :
  0 <= value < 4294967296 =>
  size encoded = 4 =>
  (forall position, 0 <= position < 4 =>
    from_be [nth (byte_of_int 0) encoded position] =
      octet64 value (position + 4)) =>
  encoded = be32 value.
proof.
  move=> hv hs hc.
  apply (eq_from_nth (byte_of_int 0)).
  + by rewrite hs size_be32.
  move=> position hi.
  have hr : 0 <= position < 4 by smt().
  have hleft := hc position hr.
  have hright := be32_low_octet64 value position hv hr.
  apply byte_numeric_injective; smt().
qed.
