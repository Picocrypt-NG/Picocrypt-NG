require import AllCore List Distr.
require import RecordFraming BigEndianFields RecordIntegrity RecordConfidentiality.

(* One payload-MAC key and one fixed profile. The selected profile, key
   provenance, primitive security and authenticated geometry are external.
   No VolumeID is present in the actual D1 outer record MAC frame. *)
op session_profile : int.
type d1_record = int * int * int * bool * bytes.

op frame_valid (r : d1_record) : bool =
  0 <= r.`1 < 65536 /\ 0 <= r.`2 < 18446744073709551616 /\
  0 <= r.`3 < 4294967296 /\ size r.`5 = r.`3.
op source_admitted (r : d1_record) : bool =
  (r.`1 = 257 \/ r.`1 = 258) /\ 0 <= r.`2 < 281474976710656 /\
  (if r.`4 then 0 <= r.`3 < 1048576 else r.`3 = 1048576) /\
  size r.`5 = r.`3.
op session_admitted (r : d1_record) : bool =
  source_admitted r /\ r.`1 = session_profile.
op encode (r : d1_record) : bytes =
  d1_outer_prefix r.`1 r.`2 r.`3 r.`4 ++ r.`5.

lemma source_frame_valid r : source_admitted r => frame_valid r.
proof. by rewrite /source_admitted /frame_valid; smt(). qed.

lemma encode_injective (r s : d1_record) :
  frame_valid r => frame_valid s => encode r = encode s => r = s.
proof.
  rewrite /frame_valid /encode /d1_outer_prefix -!catA.
  move=> [hrp [hri [hrl hrc]]] [hsp [hsi [hsl hsc]]] he.
  move: he; rewrite (eqseq_cat _ _ _ _) // => -[_ he].
  have [hp h0] : be 2 r.`1 = be 2 s.`1 /\
    be64 r.`2 ++ (be32 r.`3 ++ ([byte_of_int (if r.`4 then 1 else 0)] ++ r.`5)) =
    be64 s.`2 ++ (be32 s.`3 ++ ([byte_of_int (if s.`4 then 1 else 0)] ++ s.`5)).
  + by move: he; rewrite (eqseq_cat _ _ _ _) 1:!size_be //.
  have hprofile : r.`1 = s.`1.
  + have h := congr1 from_be _ _ hp.
    have hp16 : 2^16 = 65536 by ring.
    by move: h; rewrite !from_beK //= hp16.
  have [hi h1] : be64 r.`2 = be64 s.`2 /\
    be32 r.`3 ++ ([byte_of_int (if r.`4 then 1 else 0)] ++ r.`5) =
    be32 s.`3 ++ ([byte_of_int (if s.`4 then 1 else 0)] ++ s.`5).
  + by move: h0; rewrite (eqseq_cat _ _ _ _) 1:!size_be64.
  have hindex : r.`2 = s.`2 by apply be64_injective.
  have [hl h2] : be32 r.`3 = be32 s.`3 /\
    [byte_of_int (if r.`4 then 1 else 0)] ++ r.`5 =
    [byte_of_int (if s.`4 then 1 else 0)] ++ s.`5.
  + by move: h1; rewrite (eqseq_cat _ _ _ _) 1:!size_be32.
  have hlength : r.`3 = s.`3 by apply be32_injective.
  have hfinal : r.`4 = s.`4.
  + by case (r.`4); case (s.`4); smt(byte_zero_one).
  by smt().
qed.

(* The production length guard already determines final. Thus a final-byte
   omission alone is not an admitted-record collision; index omission is. *)
lemma admitted_length_determines_final r s :
  source_admitted r => source_admitted s => r.`3 = s.`3 => r.`4 = s.`4.
proof. by rewrite /source_admitted; smt(). qed.

module type D1Oracle = {
  proc sign(candidate : d1_record) : tag
}.
module type D1Adversary(O : D1Oracle) = {
  proc forge() : d1_record * tag
}.
module D1SigningOracle = {
  var secret : key
  var queries : d1_record list

  proc sign(candidate : d1_record) : tag = {
    var result : tag;
    result <- witness;
    if (session_admitted candidate) {
      queries <- candidate :: queries;
      result <- mac secret (encode candidate);
    }
    return result;
  }
}.
module D1RecordGame(A : D1Adversary) = {
  module Adversary = A(D1SigningOracle)

  proc main() : bool = {
    var candidate : d1_record;
    var candidate_tag : tag;
    D1SigningOracle.secret <$ dkey;
    D1SigningOracle.queries <- [];
    (candidate, candidate_tag) <@ Adversary.forge();
    return session_admitted candidate /\
      verify D1SigningOracle.secret (encode candidate) candidate_tag /\
      !(candidate \in D1SigningOracle.queries);
  }
}.
module D1Lift(O : ByteOracle) = {
  proc sign(candidate : d1_record) : tag = {
    var result : tag;
    result <- witness;
    if (session_admitted candidate) {
      result <@ O.sign(encode candidate);
    }
    return result;
  }
}.
module D1Reduce(A : D1Adversary, O : ByteOracle) = {
  module Adversary = A(D1Lift(O))

  proc forge() : bytes * tag = {
    var candidate : d1_record;
    var candidate_tag : tag;
    (candidate, candidate_tag) <@ Adversary.forge();
    return (encode candidate, candidate_tag);
  }
}.

lemma encoded_fresh (candidate : d1_record) (queries : d1_record list) :
  session_admitted candidate => all session_admitted queries =>
  !(candidate \in queries) => !(encode candidate \in map encode queries).
proof.
  move=> hc hq hf.
  apply/negP => /mapP [previous [hm he]].
  have hp : session_admitted previous by smt(allP).
  have hv : frame_valid candidate /\ frame_valid previous
    by smt(source_frame_valid).
  have heq : previous = candidate by smt(encode_injective).
  by smt().
qed.

section Reduction.
  declare module A <: D1Adversary {-D1SigningOracle, -MACOracle}.

  lemma d1_record_integrity_reduction &m :
    Pr[D1RecordGame(A).main() @ &m : res] <=
    Pr[UFCMA(D1Reduce(A)).main() @ &m : res].
  proof.
    byequiv => //=.
    proc; inline *; wp.
    call (_ : D1SigningOracle.secret{1} = MACOracle.secret{2} /\
      all session_admitted D1SigningOracle.queries{1} /\
      map encode D1SigningOracle.queries{1} = MACOracle.queries{2}).
    + proc; inline *; sp; auto => />; smt().
    wp; rnd; auto => />; smt(encoded_fresh).
  qed.
end section Reduction.

(* A complete supplied outer profile fixes every slot and its order. This
   conditional semantic statement does not construct/authenticate the Go
   geometry, establish physical EOF, check bootstraps or compose the inner
   volume. A D1 final carries any sub-chunk length, including zero. *)
type d1_slot = int * int * int * bool * int.
type d1_profile = d1_slot list.
type d1_transcript = (d1_record * tag) list.
op slot_of (r : d1_record) : d1_slot = (r.`1, r.`2, r.`3, r.`4, size r.`5).
op semantics (t : d1_transcript) : d1_record list = map fst t.
op valid_slot (s : d1_slot) : bool =
  (s.`1 = 257 \/ s.`1 = 258) /\ 0 <= s.`2 < 281474976710656 /\
  (if s.`4 then 0 <= s.`3 < 1048576 else s.`3 = 1048576) /\ s.`5 = s.`3.
op valid_profile (p : d1_profile) : bool =
  0 < size p <= 281474976710656 /\ all valid_slot p /\
  uniq (map (fun s : d1_slot => s.`2) p) /\
  all (fun s : d1_slot => s.`1 = session_profile) p /\
  (forall i, 0 <= i < size p =>
    (nth witness p i).`2 = i /\ (nth witness p i).`4 = (i = size p - 1)) /\
  (size p = 1 => 16 <= (head witness p).`3).
op fits (p : d1_profile) (rs : d1_record list) : bool = map slot_of rs = p.
op accepted (secret : key) (p : d1_profile) (t : d1_transcript) : bool =
  valid_profile p /\ fits p (semantics t) /\
  all (fun x : d1_record * tag => verify secret (encode x.`1) x.`2) t.
op first_fresh (issued : d1_record list) (t : d1_transcript) : d1_record * tag =
  nth witness t (find (fun x : d1_record * tag => !(x.`1 \in issued)) t).

lemma fits_admitted p rs :
  valid_profile p => fits p rs => all session_admitted rs.
proof.
  rewrite /valid_profile /fits.
  move=> [_ [hp [_ [hc _]]]] hfit.
  apply/allP=> r hr.
  have hs : slot_of r \in p by rewrite -hfit; apply/map_f.
  have hv : valid_slot (slot_of r) by smt(allP).
  have hprofile : (slot_of r).`1 = session_profile by smt(allP).
  by move: hv hprofile; rewrite /valid_slot /slot_of /session_admitted /source_admitted /=.
qed.

lemma accepted_exact_count secret p t : accepted secret p t => size t = size p.
proof.
  move=> [_ [hf _]].
  have h := congr1 size _ _ hf.
  by move: h; rewrite /semantics !size_map.
qed.

lemma accepted_canonical_position secret p t i :
  accepted secret p t => 0 <= i < size t =>
  (nth witness (semantics t) i).`2 = i /\
  (nth witness (semantics t) i).`4 = (i = size t - 1).
proof.
  move=> ha hi.
  have hc := accepted_exact_count secret p t ha.
  have [hp [hf hv]] := ha.
  have hs : size (semantics t) = size t by rewrite /semantics size_map.
  have hn := nth_map (witness<:d1_record>) (witness<:d1_slot>) slot_of
    i (semantics t) _; first by smt().
  have hfit : map slot_of (semantics t) = p by exact hf.
  have hposition : forall j, 0 <= j < size p =>
    (nth witness p j).`2 = j /\ (nth witness p j).`4 = (j = size p - 1)
    by move: hp; rewrite /valid_profile; smt().
  have h := hposition i _; first by smt().
  by move: hn h; rewrite hfit /slot_of /=; smt().
qed.

lemma accepted_final_record secret p t :
  accepted secret p t => (last witness (semantics t)).`4 /\
    0 <= size (last witness (semantics t)).`5 < 1048576.
proof.
  move=> [hp [hf hv]].
  have hs : size (semantics t) = size p.
  + have h := congr1 size _ _ hf; by move: h; rewrite size_map.
  have hrange : 0 <= size p - 1 < size p by move: hp; rewrite /valid_profile; smt().
  have hn := nth_map (witness<:d1_record>) (witness<:d1_slot>) slot_of
    (size p - 1) (semantics t) _.
  + by smt().
  have hfit : map slot_of (semantics t) = p by exact hf.
  have hl : slot_of (last witness (semantics t)) = last witness p.
  + by move: hn; rewrite hfit nth_last -hs nth_last; smt().
  have hfinal : (last witness p).`4.
  + have hposition : forall i, 0 <= i < size p =>
      (nth witness p i).`2 = i /\ (nth witness p i).`4 = (i = size p - 1)
      by move: hp; rewrite /valid_profile; smt().
    have h := hposition (size p - 1) hrange.
    by move: h; rewrite nth_last; smt().
  have ha := fits_admitted p (semantics t) hp hf.
  have hm : last witness (semantics t) \in semantics t.
  + rewrite -nth_last; apply mem_nth; smt().
  have had : session_admitted (last witness (semantics t)) by smt(allP).
  by move: hl hfinal had; rewrite /slot_of /session_admitted /source_admitted /=; smt().
qed.

lemma differing_stream_has_fresh p issued t :
  valid_profile p => fits p issued => fits p (semantics t) =>
  semantics t <> issued => has (fun x : d1_record * tag => !(x.`1 \in issued)) t.
proof.
  move=> hp hi ht hd.
  have hu : uniq (map slot_of issued).
  + have hindices : uniq (map (fun s : d1_slot => s.`2) p)
      by move: hp; rewrite /valid_profile; smt().
    rewrite hi; exact (uniq_map (fun s : d1_slot => s.`2) p hindices).
  have hnot : !has (fun x : d1_record * tag => !(x.`1 \in issued)) t => false.
  + move=> hn.
    have hall : all (fun r : d1_record => r \in issued) (semantics t).
    + rewrite /semantics all_map; by smt(hasPn allP).
    have hsame : semantics t = issued.
    + apply (in_inj_map slot_of (fun r : d1_record => r \in issued)) => //.
      + exact (map_uniq_inj_in slot_of issued hu).
      + by apply/allP.
      + by move: hi ht; rewrite /fits; smt().
    by smt().
  by smt().
qed.

lemma accepted_difference_extracts_byte_forgery secret p issued queries t :
  fits p issued => all (fun r : d1_record => r \in issued) queries =>
  accepted secret p t => semantics t <> issued =>
  verify secret (encode (first_fresh issued t).`1) (first_fresh issued t).`2 /\
  !(encode (first_fresh issued t).`1 \in map encode queries).
proof.
  move=> hi hq [hp [ht hv]] hd.
  have hh := differing_stream_has_fresh p issued t hp hi ht hd.
  have hf : !((first_fresh issued t).`1 \in issued).
  + exact (nth_find witness (fun x : d1_record * tag => !(x.`1 \in issued)) t hh).
  have hm : first_fresh issued t \in t.
  + rewrite /first_fresh; apply mem_nth; smt(find_ge0 has_find).
  have hr : (first_fresh issued t).`1 \in semantics t.
  + rewrite /semantics; exact (map_f fst t (first_fresh issued t) hm).
  have ha := fits_admitted p (semantics t) hp ht.
  have hqi := fits_admitted p issued hp hi.
  have hc : session_admitted (first_fresh issued t).`1 by smt(allP).
  have hqa : all session_admitted queries by smt(allP).
  have hqf : !((first_fresh issued t).`1 \in queries) by smt(allP).
  have hbyte := encoded_fresh (first_fresh issued t).`1 queries hc hqa hqf.
  by smt(allP).
qed.

(* Source-admitted positive fixture: an empty inner stream has a 16-byte outer
   marker/length prefix carried in its sole final record. *)
op data_final : d1_record = (257, 0, 16, true, nseq 16 (byte_of_int 0)).
op second_data_final : d1_record = (257, 1, 16, true, nseq 16 (byte_of_int 0)).

lemma data_final_profile_valid :
  session_profile = 257 => valid_profile [slot_of data_final].
proof.
  move=> hp; rewrite /valid_profile /valid_slot /slot_of /data_final
    /= !size_nseq hp /=.
  move=> i hi; have -> : i = 0 by smt().
  by done.
qed.

lemma signed_data_final_accepted secret :
  session_profile = 257 =>
  (forall message, verify secret message (mac secret message)) =>
  accepted secret [slot_of data_final] [(data_final, mac secret (encode data_final))].
proof.
  move=> hp correct.
  by rewrite /accepted (data_final_profile_valid hp) /fits /semantics /=; apply correct.
qed.

op full_record : d1_record =
  (257, 0, 1048576, false, nseq 1048576 (byte_of_int 0)).
op empty_final : d1_record = (257, 1, 0, true, []).

lemma empty_final_after_full_profile_valid :
  session_profile = 257 => valid_profile [slot_of full_record; slot_of empty_final].
proof.
  move=> hp; rewrite /valid_profile /valid_slot /slot_of /full_record /empty_final
    /= !size_nseq hp /=.
  move=> i hi.
  have [->|->] : i = 0 \/ i = 1 by smt().
  + by done.
  + by done.
qed.

op encode_without_index (r : d1_record) : bytes =
  d1_outer_domain ++ (be 2 r.`1 ++
    (be32 r.`3 ++ ([byte_of_int (if r.`4 then 1 else 0)] ++ r.`5))).

lemma omitted_index_collision :
  source_admitted data_final /\ source_admitted second_data_final /\
  data_final <> second_data_final /\
  encode_without_index data_final = encode_without_index second_data_final.
proof.
  by rewrite /source_admitted /data_final /second_data_final
    /encode_without_index /= !size_nseq.
qed.

lemma omitted_index_alias :
  encode_without_index data_final = encode_without_index second_data_final.
proof. by have h := omitted_index_collision; smt(). qed.
