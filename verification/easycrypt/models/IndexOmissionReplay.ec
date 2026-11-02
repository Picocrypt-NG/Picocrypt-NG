require import AllCore List Distr.
require import RecordFraming RecordIntegrity.

axiom keygen_lossless : is_lossless dkey.
axiom mac_correct (secret : key) (message : bytes) :
  verify secret message (mac secret message).

module MutantOracle = {
  var secret : key
  var queries : record list

  proc sign(candidate : record) : tag = {
    var result : tag;
    result <- witness;
    if (valid_record candidate) {
      queries <- candidate :: queries;
      result <- mac secret (encode_without_index candidate);
    }
    return result;
  }
}.

module Replay(O : StructuredOracle) = {
  proc forge() : record * tag = {
    var candidate_tag : tag;
    candidate_tag <@ O.sign(replay_zero);
    return (replay_one, candidate_tag);
  }
}.

module MutantGame(A : StructuredAdversary) = {
  module Adversary = A(MutantOracle)

  proc main() : bool = {
    var candidate : record;
    var candidate_tag : tag;
    MutantOracle.secret <$ dkey;
    MutantOracle.queries <- [];
    (candidate, candidate_tag) <@ Adversary.forge();
    return valid_record candidate /\
      verify MutantOracle.secret (encode_without_index candidate) candidate_tag /\
      !(candidate \in MutantOracle.queries);
  }
}.

lemma index_omission_replay &m :
  Pr[MutantGame(Replay).main() @ &m : res] = 1%r.
proof.
  byphoare (_ : true ==> res) => //.
  proc; inline *; auto => />;
    smt(keygen_lossless mac_correct mutant_index_collision).
qed.
