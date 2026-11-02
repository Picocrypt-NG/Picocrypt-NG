require import AllCore List Distr.
require import RecordFraming.

type key.
type tag.
op dkey : key distr.
op mac : key -> bytes -> tag.
op verify : key -> bytes -> tag -> bool.

module type ByteOracle = {
  proc sign(message : bytes) : tag
}.

module type ByteAdversary(O : ByteOracle) = {
  proc forge() : bytes * tag
}.

module MACOracle = {
  var secret : key
  var queries : bytes list

  proc sign(message : bytes) : tag = {
    queries <- message :: queries;
    return mac secret message;
  }
}.

module UFCMA(A : ByteAdversary) = {
  module Adversary = A(MACOracle)

  proc main() : bool = {
    var message : bytes;
    var candidate_tag : tag;
    MACOracle.secret <$ dkey;
    MACOracle.queries <- [];
    (message, candidate_tag) <@ Adversary.forge();
    return verify MACOracle.secret message candidate_tag /\
      !(message \in MACOracle.queries);
  }
}.

module type StructuredOracle = {
  proc sign(candidate : record) : tag
}.

module type StructuredAdversary(O : StructuredOracle) = {
  proc forge() : record * tag
}.

module RecordOracle = {
  var secret : key
  var queries : record list

  proc sign(candidate : record) : tag = {
    var result : tag;
    result <- witness;
    if (valid_record candidate) {
      queries <- candidate :: queries;
      result <- mac secret (encode candidate);
    }
    return result;
  }
}.

module RecordGame(A : StructuredAdversary) = {
  module Adversary = A(RecordOracle)

  proc main() : bool = {
    var candidate : record;
    var candidate_tag : tag;
    RecordOracle.secret <$ dkey;
    RecordOracle.queries <- [];
    (candidate, candidate_tag) <@ Adversary.forge();
    return valid_record candidate /\
      verify RecordOracle.secret (encode candidate) candidate_tag /\
      !(candidate \in RecordOracle.queries);
  }
}.

module Lift(O : ByteOracle) = {
  proc sign(candidate : record) : tag = {
    var result : tag;
    result <- witness;
    if (valid_record candidate) {
      result <@ O.sign(encode candidate);
    }
    return result;
  }
}.

module Reduce(A : StructuredAdversary, O : ByteOracle) = {
  module Adversary = A(Lift(O))

  proc forge() : bytes * tag = {
    var candidate : record;
    var candidate_tag : tag;
    (candidate, candidate_tag) <@ Adversary.forge();
    return (encode candidate, candidate_tag);
  }
}.

lemma encoded_fresh (candidate : record) (queries : record list) :
  valid_record candidate => all valid_record queries =>
  !(candidate \in queries) => !(encode candidate \in map encode queries).
proof.
  move=> candidate_valid queries_valid candidate_fresh.
  apply/negP => /mapP [previous [previous_signed same_encoding]].
  have previous_valid : valid_record previous by smt(allP).
  have same_record : previous = candidate by smt(encode_injective).
  by smt().
qed.

section Reduction.
  declare module A <: StructuredAdversary {-RecordOracle, -MACOracle}.

  lemma record_integrity_reduction &m :
    Pr[RecordGame(A).main() @ &m : res] <=
    Pr[UFCMA(Reduce(A)).main() @ &m : res].
  proof.
    byequiv => //=.
    proc; inline *; wp.
    call (_ : RecordOracle.secret{1} = MACOracle.secret{2} /\
      all valid_record RecordOracle.queries{1} /\
      map encode RecordOracle.queries{1} = MACOracle.queries{2}).
    + proc.
      inline *.
      sp.
      auto => />; smt().
    wp; rnd; auto => />; smt(encoded_fresh).
  qed.
end section Reduction.
