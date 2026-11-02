require import AllCore List.
require import RecordFraming CanonicalRecords BigEndianFields NormalStream.
require SafeCastRepresentation.

op canonical_slot (commitment : bytes) (length index : int) : slot =
  let count = canonical_count length in
  let final = index = count in
  let body_length = if final then 0 else chunk_length length index in
  (commitment, be64 index, descriptor_tail body_length final, body_length).

op canonical_profile (commitment : bytes) (length : int) : profile =
  mkseq (canonical_slot commitment length) (canonical_count length + 1).

lemma canonical_profile_size (commitment : bytes) (length : int) :
  SafeCastRepresentation.uint64_domain length =>
  size (canonical_profile commitment length) = canonical_count length + 1.
proof.
  move=> hinput.
  have hb := canonical_count_bound length hinput.
  by rewrite /canonical_profile size_mkseq; smt().
qed.

lemma canonical_profile_slot (commitment : bytes) (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  nth witness (canonical_profile commitment length) index =
    canonical_slot commitment length index.
proof.
  move=> hinput hindex.
  by rewrite /canonical_profile nth_mkseq; smt().
qed.

lemma canonical_profile_indices_unique (commitment : bytes) (length : int) :
  SafeCastRepresentation.uint64_domain length =>
  uniq (map (fun s : slot => s.`2) (canonical_profile commitment length)).
proof.
  move=> hinput.
  rewrite /canonical_profile map_mkseq /canonical_slot /= /mkseq.
  have hinj : forall i j,
    i \in iota_ 0 (canonical_count length + 1) =>
    j \in iota_ 0 (canonical_count length + 1) =>
    be64 i = be64 j => i = j.
  + move=> i j.
    rewrite !mem_iota /= => hi hj he.
    have hir := reachable_final_index length i hinput _.
    + by smt().
    have hjr := reachable_final_index length j hinput _.
    + by smt().
    apply (be64_injective i j) => //.
    + by move: hir; rewrite /SafeCastRepresentation.uint64_domain
        /SafeCastRepresentation.uint64_modulus; smt().
    + by move: hjr; rewrite /SafeCastRepresentation.uint64_domain
        /SafeCastRepresentation.uint64_modulus; smt().
  by rewrite (map_inj_in_uniq _ _ hinj) iota_uniq.
qed.

lemma canonical_slot_valid (commitment : bytes) (length index : int) :
  size commitment = 32 =>
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  valid_slot (canonical_slot commitment length index).
proof.
  move=> hcommit hinput hindex.
  rewrite /canonical_slot /valid_slot /= size_be64 size_descriptor_tail
    descriptor_tail_reserved hcommit /=.
  case (index = canonical_count length) => hfinal /=; first by done.
  have hc := canonical_chunk_bounds length index hinput _.
  + by smt().
  by move: hc; rewrite /chunk_size; smt().
qed.

lemma canonical_profile_valid (commitment : bytes) (length : int) :
  size commitment = 32 =>
  SafeCastRepresentation.uint64_domain length =>
  valid_profile (canonical_profile commitment length).
proof.
  move=> hcommit hinput.
  have hb := canonical_count_bound length hinput.
  have hr := reachable_final_index length 0 hinput _.
  + by smt().
  have hs := canonical_profile_size commitment length hinput.
  have hu := canonical_profile_indices_unique commitment length hinput.
  rewrite /valid_profile hs.
  split.
  + by move: hb hr; rewrite /maximum_record_count; smt().
  split.
  + apply/allP=> s.
    rewrite /canonical_profile mkseqP => -[i [hi ->]].
    apply canonical_slot_valid => //.
    by smt().
  split; first exact hu.
  split.
  + apply/allP=> s.
    rewrite /canonical_profile mkseqP => -[i [hi ->]].
    have hzero : 0 <= 0 <= canonical_count length by smt().
    have hhead := canonical_profile_slot commitment length 0 hinput hzero.
    by rewrite -nth0_head hhead /canonical_slot /=.
  move=> i hi.
  have hir : 0 <= i <= canonical_count length by smt().
  rewrite (canonical_profile_slot commitment length i hinput hir) /=.
  case (i = canonical_count length) => hfinal /=.
  + by rewrite /canonical_slot hfinal /= descriptor_tail_final_zero /final_tail.
  rewrite /canonical_slot /= descriptor_tail_flag.
  have hc := canonical_chunk_bounds length i hinput _.
  + by smt().
  have hp := preceding_chunks_full length i hinput.
  by move: hc hp; rewrite /chunk_size; smt().
qed.

lemma canonical_profile_final (commitment : bytes) (length : int) :
  size commitment = 32 =>
  SafeCastRepresentation.uint64_domain length =>
  (last witness (canonical_profile commitment length)).`2 =
    be64 (canonical_count length) /\
  (last witness (canonical_profile commitment length)).`3 = final_tail /\
  (last witness (canonical_profile commitment length)).`4 = 0.
proof.
  move=> hcommit hinput.
  have hb := canonical_count_bound length hinput.
  have hs := canonical_profile_size commitment length hinput.
  have hn := canonical_profile_slot commitment length
    (canonical_count length) hinput _.
  + by smt().
  rewrite -nth_last hs /= hn /canonical_slot /=.
  by rewrite descriptor_tail_final_zero /final_tail.
qed.

lemma canonical_profile_index_value (commitment : bytes) (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  from_be (nth witness (canonical_profile commitment length) index).`2 = index.
proof.
  move=> hinput hindex.
  have hi := reachable_final_index length index hinput hindex.
  rewrite (canonical_profile_slot commitment length index hinput hindex)
    /canonical_slot /=.
  apply from_be64K.
  by move: hi; rewrite /SafeCastRepresentation.uint64_domain
    /SafeCastRepresentation.uint64_modulus; smt().
qed.

lemma canonical_profile_length_value (commitment : bytes) (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  let s = nth witness (canonical_profile commitment length) index in
  from_be (take 4 s.`3) = s.`4.
proof.
  move=> hinput hindex /=.
  rewrite (canonical_profile_slot commitment length index hinput hindex)
    /canonical_slot /=.
  apply descriptor_tail_length.
  case (index = canonical_count length) => hfinal /=; first by done.
  have hc := canonical_chunk_bounds length index hinput _.
  + by smt().
  by move: hc; rewrite /chunk_size; smt().
qed.

lemma canonical_empty_profile :
  canonical_profile (nseq 32 (byte_of_int 0)) 0 = empty_profile.
proof.
  rewrite /canonical_profile canonical_count_zero /= mkseq1 /canonical_slot
    canonical_count_zero /= be64_zero descriptor_tail_final_zero.
  by rewrite /empty_profile /slot_of /empty_final /final_tail.
qed.
