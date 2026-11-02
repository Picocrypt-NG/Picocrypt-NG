require import AllCore List BitEncoding.
require BitWord.

clone BitWord as Byte with
  op n <- 8
proof gt0_n by done.

type byte = Byte.word.
type bytes = byte list.
type record = bytes * bytes * bytes * bytes.

op byte_of_int (n : int) : byte = Byte.mkword (BS2Int.int2bs 8 n).

op domain : bytes = map byte_of_int
  [80; 105; 99; 111; 99; 114; 121; 112; 116; 45; 78; 71; 47;
   80; 67; 86; 51; 47; 114; 101; 99; 111; 114; 100; 0].

(* Fields are commitment32, canonical index bytes, descriptor tail, ciphertext.
   Numeric BE64 refinement and the tail's production constraints are external. *)
op valid_record (r : record) : bool =
  size r.`1 = 32 /\ size r.`2 = 8 /\ size r.`3 = 8.

op encode (r : record) : bytes =
  domain ++ (r.`1 ++ (r.`2 ++ (r.`3 ++ r.`4))).

op encode_without_index (r : record) : bytes =
  domain ++ (r.`1 ++ (r.`3 ++ r.`4)).

lemma encode_injective (r s : record) :
  valid_record r => valid_record s => encode r = encode s => r = s.
proof.
rewrite /valid_record.
move=> [hrc [hri hrt]] [hsc [hsi hst]] he.
have h0 : r.`1 ++ (r.`2 ++ (r.`3 ++ r.`4)) =
  s.`1 ++ (s.`2 ++ (s.`3 ++ s.`4)).
+ have hd := congr1 (fun z : bytes => drop (size domain) z) _ _ he.
  move: hd.
  by rewrite /= /encode !drop_size_cat.
have hcsize : size r.`1 = size s.`1 by smt().
have hisize : size r.`2 = size s.`2 by smt().
have htsize : size r.`3 = size s.`3 by smt().
have [hc h1] : r.`1 = s.`1 /\
  r.`2 ++ (r.`3 ++ r.`4) = s.`2 ++ (s.`3 ++ s.`4)
  by smt(eqseq_cat).
have [hi h2] : r.`2 = s.`2 /\ r.`3 ++ r.`4 = s.`3 ++ s.`4
  by smt(eqseq_cat).
have [ht hx] : r.`3 = s.`3 /\ r.`4 = s.`4 by smt(eqseq_cat).
by smt().
qed.

lemma byte_zero_one : byte_of_int 0 <> byte_of_int 1.
proof.
apply/negP=> he.
have h := congr1 (fun b : byte => nth false (Byte.ofword b) 0) _ _ he.
move: h.
rewrite /= /byte_of_int !Byte.ofwordK ?BS2Int.size_int2bs //.
by rewrite BS2Int.int2bs0 BS2Int.int2bs1 //= nth_nseq.
qed.

op index_zero : bytes = nseq 8 (byte_of_int 0).
op index_one : bytes = nseq 7 (byte_of_int 0) ++ [byte_of_int 1].
op replay_tail : bytes =
  [byte_of_int 0; byte_of_int 16; byte_of_int 0; byte_of_int 0] ++
  nseq 4 (byte_of_int 0).
op replay_zero : record =
  (nseq 32 (byte_of_int 0), index_zero, replay_tail, nseq 1048576 (byte_of_int 0)).
op replay_one : record =
  (nseq 32 (byte_of_int 0), index_one, replay_tail, nseq 1048576 (byte_of_int 0)).

lemma replay_records_valid : valid_record replay_zero /\ valid_record replay_one.
proof.
by rewrite /valid_record /replay_zero /replay_one /index_zero /index_one
  /replay_tail /= !size_cat !size_nseq.
qed.

lemma replay_records_distinct : replay_zero <> replay_one.
proof.
have hi : index_zero <> index_one.
+ have hz : nth (byte_of_int 0) index_zero 7 = byte_of_int 0.
  + by rewrite /index_zero nth_nseq.
  have ho : nth (byte_of_int 0) index_one 7 = byte_of_int 1.
  + by rewrite /index_one nth_cat size_nseq /=.
  by smt(byte_zero_one).
by rewrite /replay_zero /replay_one; smt().
qed.

lemma mutant_index_collision :
  valid_record replay_zero /\ valid_record replay_one /\
  replay_zero <> replay_one /\
  encode_without_index replay_zero = encode_without_index replay_one.
proof.
have hv := replay_records_valid.
have hd := replay_records_distinct.
by rewrite /encode_without_index /replay_zero /replay_one /=; smt().
qed.
