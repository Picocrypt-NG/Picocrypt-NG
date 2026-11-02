require import AllCore List Distr.
require import RecordFraming RecordIntegrity.

(* One already-authenticated Normal profile. Its derivation from a Go logical
   core, including BE64/BE32 arithmetic, remains a separate obligation. *)
type slot = bytes * bytes * bytes * int.
type profile = slot list.
type transcript = (record * tag) list.

op slot_of (r : record) : slot = (r.`1, r.`2, r.`3, size r.`4).
op semantics (t : transcript) : record list = map fst t.
op final_tail : bytes =
  [byte_of_int 0; byte_of_int 0; byte_of_int 0; byte_of_int 0;
   byte_of_int 1; byte_of_int 0; byte_of_int 0; byte_of_int 0].

op valid_slot (s : slot) : bool =
  size s.`1 = 32 /\ size s.`2 = 8 /\ size s.`3 = 8 /\
  drop 5 s.`3 = [byte_of_int 0; byte_of_int 0; byte_of_int 0] /\
  0 <= s.`4 <= 1048576.

op valid_profile (p : profile) : bool =
  0 < size p <= 281474976710656 /\ all valid_slot p /\
  uniq (map (fun s : slot => s.`2) p) /\
  all (fun s : slot => s.`1 = (head witness p).`1) p /\
  (forall i, 0 <= i < size p =>
    let s = nth witness p i in
    if i = size p - 1 then s.`3 = final_tail /\ s.`4 = 0
    else nth (byte_of_int 0) s.`3 4 = byte_of_int 0 /\
      1 <= s.`4 <= 1048576 /\ (i < size p - 2 => s.`4 = 1048576)).

op fits (p : profile) (rs : record list) : bool = map slot_of rs = p.
op accepted (secret : key) (p : profile) (t : transcript) : bool =
  valid_profile p /\ fits p (semantics t) /\
  all (fun x : record * tag => verify secret (encode x.`1) x.`2) t.

op first_fresh (issued : record list) (t : transcript) : record * tag =
  nth witness t (find (fun x : record * tag => !(x.`1 \in issued)) t).

lemma profile_final_closure (p : profile) :
  valid_profile p =>
  (last witness p).`3 = final_tail /\ (last witness p).`4 = 0.
proof.
  move=> [hs [_ [_ [_ hp]]]].
  have hr : 0 <= size p - 1 < size p by smt().
  have h := hp (size p - 1) hr.
  by move: h; rewrite nth_last /=.
qed.

lemma accepted_exact_count (secret : key) (p : profile) (t : transcript) :
  accepted secret p t => size t = size p.
proof.
  move=> [_ [hf _]].
  move: hf; rewrite /fits /semantics => hf.
  have h := congr1 size _ _ hf.
  by move: h; rewrite !size_map.
qed.

lemma accepted_final_record (secret : key) (p : profile) (t : transcript) :
  accepted secret p t =>
  (last witness (semantics t)).`3 = final_tail /\
  (last witness (semantics t)).`4 = [].
proof.
  move=> [hp [hf hv]].
  have hs : size (semantics t) = size p.
  + move: hf; rewrite /fits => hf.
    have h := congr1 size _ _ hf.
    by move: h; rewrite size_map.
  have hpositive : 0 < size p by move: hp; rewrite /valid_profile; smt().
  have hr : 0 <= size p - 1 < size (semantics t) by smt().
  have hn := nth_map (witness<:record>) (witness<:slot>) slot_of
    (size p - 1) (semantics t) hr.
  have hfit : map slot_of (semantics t) = p by exact hf.
  have hl : slot_of (last witness (semantics t)) = last witness p.
  + by move: hn; rewrite hfit nth_last -hs nth_last; smt().
  have hc := profile_final_closure p hp.
  by move: hl hc; rewrite /slot_of /=; smt(size_eq0).
qed.

lemma fits_valid (p : profile) (rs : record list) :
  valid_profile p => fits p rs => all valid_record rs.
proof.
  rewrite /valid_profile /fits.
  move=> [_ [hp _]] hfit.
  apply/allP=> r hr.
  have hs : slot_of r \in p by rewrite -hfit; apply/map_f.
  have hv : valid_slot (slot_of r) by smt(allP).
  by move: hv; rewrite /valid_slot /slot_of /valid_record /=; smt().
qed.

lemma fits_unique (p : profile) (rs : record list) :
  valid_profile p => fits p rs => uniq (map slot_of rs).
proof.
  rewrite /valid_profile /fits.
  move=> [_ [_ [hu _]]] ->.
  exact (uniq_map (fun s : slot => s.`2) p hu).
qed.

lemma same_slots_no_fresh (issued received : record list) :
  uniq (map slot_of issued) =>
  map slot_of received = map slot_of issued =>
  all (fun r : record => r \in issued) received => received = issued.
proof.
  move=> hu hm ha.
  apply (in_inj_map slot_of (fun r : record => r \in issued)) => //.
  + exact (map_uniq_inj_in slot_of issued hu).
  + by apply/allP.
qed.

lemma differing_stream_has_fresh (p : profile) (issued : record list)
    (t : transcript) :
  valid_profile p => fits p issued => fits p (semantics t) =>
  semantics t <> issued =>
  has (fun x : record * tag => !(x.`1 \in issued)) t.
proof.
  move=> hp hi ht hd.
  have hn : !has (fun x : record * tag => !(x.`1 \in issued)) t => false.
  + move=> hn.
    have hall : all (fun r : record => r \in issued) (semantics t).
    + rewrite /semantics all_map.
      by smt(hasPn allP).
    have hu := fits_unique p issued hp hi.
    have he : semantics t = issued.
    + apply (same_slots_no_fresh issued (semantics t)) => //.
      by move: hi ht; rewrite /fits; smt().
    by smt().
  by smt().
qed.

lemma accepted_difference_extracts_forgery (secret : key) (p : profile)
    (issued queries : record list) (t : transcript) :
  fits p issued => all (fun r : record => r \in issued) queries =>
  accepted secret p t => semantics t <> issued =>
  valid_record (first_fresh issued t).`1 /\
  verify secret (encode (first_fresh issued t).`1) (first_fresh issued t).`2 /\
  !((first_fresh issued t).`1 \in queries).
proof.
  move=> hi hq [hp [ht hv]] hd.
  have hh := differing_stream_has_fresh p issued t hp hi ht hd.
  have hf : !((first_fresh issued t).`1 \in issued).
  + exact (nth_find witness (fun x : record * tag => !(x.`1 \in issued)) t hh).
  have hm : first_fresh issued t \in t.
  + rewrite /first_fresh; apply mem_nth; smt(find_ge0 has_find).
  have hr : (first_fresh issued t).`1 \in semantics t.
  + rewrite /semantics; exact (map_f fst t (first_fresh issued t) hm).
  have ha := fits_valid p (semantics t) hp ht.
  by smt(allP).
qed.

lemma empty_transcript_rejected (secret : key) (p : profile) :
  !accepted secret p [].
proof.
  by rewrite /accepted /fits /semantics /valid_profile /=; smt().
qed.

lemma rev_take_step (rs : record list) (i : int) :
  0 <= i < size rs =>
  rev (take (i + 1) rs) = nth witness rs i :: rev (take i rs).
proof.
  by move=> hi; rewrite (take_nth witness i rs hi) rev_rcons.
qed.

(* The adversary chooses one complete issued semantic stream before receiving
   tags, then returns one candidate transcript. It gets no signing oracle. *)
module type StreamAdversary = {
  proc issue() : profile * record list
  proc forge(issued : transcript) : transcript
}.

module SessionState = {
  var expected : profile
  var issued : record list
  var received : transcript
}.

module ExtractStream(A : StreamAdversary, O : StructuredOracle) = {
  proc forge() : record * tag = {
    var signed : transcript;
    var candidate_tag : tag;
    var r : record;
    var i : int;
    (SessionState.expected, SessionState.issued) <@ A.issue();
    SessionState.received <- [];
    signed <- [];
    i <- 0;
    if (valid_profile SessionState.expected /\
        fits SessionState.expected SessionState.issued) {
      while (i < size SessionState.issued) {
        r <- nth witness SessionState.issued i;
        candidate_tag <@ O.sign(r);
        signed <- rcons signed (r, candidate_tag);
        i <- i + 1;
      }
      SessionState.received <@ A.forge(signed);
    }
    return first_fresh SessionState.issued SessionState.received;
  }
}.

section StreamReduction.
  declare module A <: StreamAdversary {-RecordOracle, -MACOracle, -SessionState}.

  lemma issuance_exact :
    hoare[ExtractStream(A, RecordOracle).forge : RecordOracle.queries = [] ==>
      (valid_profile SessionState.expected /\
       fits SessionState.expected SessionState.issued) =>
      RecordOracle.queries = rev SessionState.issued].
  proof.
    proc; inline *; wp.
    seq 4 : (i = 0 /\ RecordOracle.queries = []).
    + wp; call (_ : true); auto.
    if.
    + call (_ : true).
      while (0 <= i <= size SessionState.issued /\
        valid_profile SessionState.expected /\
        fits SessionState.expected SessionState.issued /\
        RecordOracle.queries = rev (take i SessionState.issued)).
      + auto => />; smt(fits_valid mem_nth allP rev_take_step).
      skip => &hr [[hi hq] [hp hf]].
      split; first by rewrite hi hq hp hf take0 rev_nil /=; apply size_ge0.
      by move=> queries i0 hnot [hrange [hp0 [hf0 hq0]]]; smt(take_size).
    by auto => />; smt().
  qed.

  lemma extraction_sound :
    hoare[RecordGame(ExtractStream(A)).main : true ==>
      (accepted RecordOracle.secret SessionState.expected SessionState.received /\
       semantics SessionState.received <> SessionState.issued) => res].
  proof.
    proc; inline *; wp.
    seq 6 : (i = 0 /\ SessionState.received = [] /\
      all (fun r : record => r \in SessionState.issued) RecordOracle.queries).
    + wp; call (_ : true); wp; rnd; auto => />.
    if.
    + call (_ : true).
      while (0 <= i <= size SessionState.issued /\
        valid_profile SessionState.expected /\
        fits SessionState.expected SessionState.issued /\
        all (fun r : record => r \in SessionState.issued) RecordOracle.queries).
      + auto => />; smt(mem_nth allP).
      skip => &hr [[hi [hrecv hq]] [hp hf]].
      split; first by rewrite hi hp hf hq /=; apply size_ge0.
      move=> queries i0 hnot [hrange [hp0 [hf0 hq0]]] result0 /= [ha hd].
      exact (accepted_difference_extracts_forgery RecordOracle.secret{hr}
        SessionState.expected{hr} SessionState.issued{hr} queries result0
        hf0 hq0 ha hd).
    skip => &hr [[hi [hrecv hq]] hn].
    rewrite hrecv; smt(empty_transcript_rejected).
  qed.

  lemma stream_origin_reduction &m :
    Pr[RecordGame(ExtractStream(A)).main() @ &m :
      accepted RecordOracle.secret SessionState.expected SessionState.received /\
      semantics SessionState.received <> SessionState.issued] <=
    Pr[UFCMA(Reduce(ExtractStream(A))).main() @ &m : res].
  proof.
    have hbad : Pr[RecordGame(ExtractStream(A)).main() @ &m :
      (accepted RecordOracle.secret SessionState.expected SessionState.received /\
       semantics SessionState.received <> SessionState.issued) /\ !res] = 0%r.
    + byphoare (_ : true ==> _) => //.
      hoare.
      by conseq extraction_sound; smt().
    have hmono : Pr[RecordGame(ExtractStream(A)).main() @ &m :
      (accepted RecordOracle.secret SessionState.expected SessionState.received /\
       semantics SessionState.received <> SessionState.issued) /\ res] <=
      Pr[RecordGame(ExtractStream(A)).main() @ &m : res]
      by rewrite Pr[mu_sub].
    have hrecord := record_integrity_reduction (ExtractStream(A)) &m.
    have hsplit : Pr[RecordGame(ExtractStream(A)).main() @ &m :
      accepted RecordOracle.secret SessionState.expected SessionState.received /\
      semantics SessionState.received <> SessionState.issued] =
      Pr[RecordGame(ExtractStream(A)).main() @ &m :
        (accepted RecordOracle.secret SessionState.expected SessionState.received /\
         semantics SessionState.received <> SessionState.issued) /\ res] +
      Pr[RecordGame(ExtractStream(A)).main() @ &m :
        (accepted RecordOracle.secret SessionState.expected SessionState.received /\
         semantics SessionState.received <> SessionState.issued) /\ !res]
      by rewrite Pr[mu_split res].
    by smt().
  qed.
end section StreamReduction.

op sign_stream (secret : key) (rs : record list) : transcript =
  map (fun r : record => (r, mac secret (encode r))) rs.

op empty_final : record =
  (nseq 32 (byte_of_int 0), index_zero, final_tail, []).
op partial_data : record =
  (nseq 32 (byte_of_int 0), index_zero,
    [byte_of_int 0; byte_of_int 0; byte_of_int 0; byte_of_int 1;
     byte_of_int 0; byte_of_int 0; byte_of_int 0; byte_of_int 0], [byte_of_int 42]).
op partial_final : record =
  (nseq 32 (byte_of_int 0), index_one, final_tail, []).
op empty_profile : profile = [slot_of empty_final].
op partial_profile : profile = [slot_of partial_data; slot_of partial_final].

lemma empty_profile_valid : valid_profile empty_profile.
proof.
  rewrite /valid_profile /empty_profile /valid_slot /slot_of /empty_final
    /final_tail /index_zero /= !size_nseq.
  by smt().
qed.

lemma partial_profile_valid : valid_profile partial_profile.
proof.
  have hi : index_zero <> index_one.
  + have hz : nth (byte_of_int 0) index_zero 7 = byte_of_int 0.
    + by rewrite /index_zero nth_nseq.
    have ho : nth (byte_of_int 0) index_one 7 = byte_of_int 1.
    + by rewrite /index_one nth_cat size_nseq /=.
    by smt(byte_zero_one).
  move: hi.
  rewrite /valid_profile /partial_profile /valid_slot /slot_of
    /partial_data /partial_final /final_tail /index_zero /index_one /=
    !size_cat !size_nseq.
  move=> hi; split; first by smt().
  split; first exact hi.
  move=> i hr.
  have [->|->] : i = 0 \/ i = 1 by smt().
  + by done.
  + by done.
qed.

lemma signed_stream_accepted (secret : key) (p : profile) (rs : record list) :
  (forall message, verify secret message (mac secret message)) =>
  valid_profile p => fits p rs => accepted secret p (sign_stream secret rs).
proof.
  move=> correct hp hf.
  rewrite /accepted /sign_stream /semantics !all_map /=.
  have hm : forall (xs : record list),
    map fst (map (fun r : record => (r, mac secret (encode r))) xs) = xs.
  + by elim=> //= r xs ->.
  by rewrite (hm rs); smt(allP).
qed.

lemma empty_plaintext_success (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  accepted secret empty_profile (sign_stream secret [empty_final]).
proof.
  move=> h; apply (signed_stream_accepted secret empty_profile [empty_final]) => //.
  exact empty_profile_valid.
qed.

lemma partial_plaintext_success (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  accepted secret partial_profile (sign_stream secret [partial_data; partial_final]).
proof.
  move=> h; apply (signed_stream_accepted secret partial_profile [partial_data; partial_final]) => //.
  exact partial_profile_valid.
qed.

lemma dropped_final_rejected (secret : key) (candidate_tag : tag) :
  !accepted secret partial_profile [(partial_data, candidate_tag)].
proof.
  by rewrite /accepted /fits /semantics /partial_profile /=; smt(size_map).
qed.

lemma extra_record_rejected (secret : key) (a b c : tag) :
  !accepted secret partial_profile
    [(partial_data, a); (partial_final, b); (partial_final, c)].
proof.
  by rewrite /accepted /fits /semantics /partial_profile /=; smt(size_map).
qed.

lemma reordered_records_rejected (secret : key) (a b : tag) :
  !accepted secret partial_profile [(partial_final, b); (partial_data, a)].
proof.
  rewrite /accepted /fits /semantics /partial_profile /slot_of
    /partial_data /partial_final /=.
  by smt().
qed.

(* These deliberately weaker acceptors isolate the guards exercised above.
   A false safety claim about them is suitable for a rejected proof control. *)
op accepted_without_shape (secret : key) (p : profile) (t : transcript) : bool =
  valid_profile p /\
  all (fun x : record * tag => slot_of x.`1 \in p /\
    verify secret (encode x.`1) x.`2) t.

op accepted_without_order (secret : key) (p : profile) (t : transcript) : bool =
  size t = size p /\ accepted_without_shape secret p t.

lemma dropped_final_mutant_accepts (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  accepted_without_shape secret partial_profile
    (sign_stream secret [partial_data]).
proof.
  move=> correct.
  by rewrite /accepted_without_shape /sign_stream /= partial_profile_valid
    /partial_profile /=; smt().
qed.

lemma extra_record_mutant_accepts (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  accepted_without_shape secret partial_profile
    (sign_stream secret [partial_data; partial_final; partial_final]).
proof.
  move=> correct.
  by rewrite /accepted_without_shape /sign_stream /= partial_profile_valid
    /partial_profile /=; smt().
qed.

lemma reordered_mutant_accepts (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  accepted_without_order secret partial_profile
    (sign_stream secret [partial_final; partial_data]).
proof.
  move=> correct.
  by rewrite /accepted_without_order /accepted_without_shape /sign_stream
    /= partial_profile_valid /partial_profile /=; smt().
qed.
