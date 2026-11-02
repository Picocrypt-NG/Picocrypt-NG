require import AllCore List Distr.
require import RecordFraming RecordIntegrity BigEndianFields.

(* One payload key/session. Independent sampling idealizes the labelled HKDF
   outputs; it is not established by distinct labels. Primitive LR security,
   secret provenance and public-context generation remain assumptions. *)
type encryption_key.
op dencryption_key : encryption_key distr.
op encrypt : encryption_key -> bytes -> bytes -> bytes.

op select (right : bool) (left_message right_message : bytes) : bytes =
  if right then right_message else left_message.
op valid_query (nonce left_message right_message : bytes) (seen : bytes list) : bool =
  size nonce = 24 /\ size left_message = size right_message /\
  size left_message <= 1048576 /\ !(nonce \in seen).
op publish (mac_key : key) (prefix ciphertext : bytes) : bytes * tag =
  (ciphertext, mac mac_key (prefix ++ ciphertext)).

(* Normal: domain || commitment32 || descriptor16 || ciphertext. *)
op normal_prefix (commitment index tail : bytes) : bytes =
  encode (commitment, index, tail, []).

lemma normal_mac_input commitment index tail ciphertext :
  normal_prefix commitment index tail ++ ciphertext =
  encode (commitment, index, tail, ciphertext).
proof. by rewrite /normal_prefix /encode /= !cats0 !catA. qed.

op d1_outer_domain : bytes = map byte_of_int
  [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;
   68;49;67;47;111;117;116;101;114;47;114;101;99;111;114;100;0].
(* Conservative record view: D1's computed framing and nonce are public here;
   this does not claim they are all visible in the actual container. *)
op d1_outer_prefix (profile index length : int) (final : bool) : bytes =
  d1_outer_domain ++ (be 2 profile ++ (be64 index ++
    (be32 length ++ [byte_of_int (if final then 1 else 0)]))).

(* Public prefix/nonce and message lengths are permitted leakage. The two
   messages share that context. No decryption or verification oracle exists. *)
module type EncryptionOracle = {
  proc query(nonce left_message right_message : bytes) : bytes option
}.
module type EncryptionAdversary(O : EncryptionOracle) = {
  proc distinguish() : bool
}.
module type PublishedOracle = {
  proc query(prefix nonce left_message right_message : bytes) : (bytes * tag) option
}.
module type PublishedAdversary(O : PublishedOracle) = {
  proc distinguish() : bool
}.

module CipherOracle = {
  var secret : encryption_key
  var right : bool
  var seen : bytes list

  proc query(nonce left_message right_message : bytes) : bytes option = {
    var result : bytes option;
    result <- None;
    if (valid_query nonce left_message right_message seen) {
      seen <- nonce :: seen;
      result <- Some (encrypt secret nonce (select right left_message right_message));
    }
    return result;
  }
}.

module EncryptionGame(A : EncryptionAdversary) = {
  module Adversary = A(CipherOracle)

  proc main(right : bool) : bool = {
    var result : bool;
    CipherOracle.secret <$ dencryption_key;
    CipherOracle.right <- right;
    CipherOracle.seen <- [];
    result <@ Adversary.distinguish();
    return result;
  }
}.

module PublishedRecordOracle = {
  var secret : encryption_key
  var mac_secret : key
  var right : bool
  var seen : bytes list

  proc query(prefix nonce left_message right_message : bytes) : (bytes * tag) option = {
    var result : (bytes * tag) option;
    var ciphertext : bytes;
    result <- None;
    if (valid_query nonce left_message right_message seen) {
      seen <- nonce :: seen;
      ciphertext <- encrypt secret nonce (select right left_message right_message);
      result <- Some (publish mac_secret prefix ciphertext);
    }
    return result;
  }
}.

module PublishedGame(A : PublishedAdversary) = {
  module Adversary = A(PublishedRecordOracle)

  proc main(right : bool) : bool = {
    var result : bool;
    PublishedRecordOracle.secret <$ dencryption_key;
    PublishedRecordOracle.mac_secret <$ dkey;
    PublishedRecordOracle.right <- right;
    PublishedRecordOracle.seen <- [];
    result <@ Adversary.distinguish();
    return result;
  }
}.

module CiphertextWrapper(O : EncryptionOracle) = {
  var mac_secret : key

  proc query(prefix nonce left_message right_message : bytes) : (bytes * tag) option = {
    var ciphertext : bytes option;
    var result : (bytes * tag) option;
    ciphertext <@ O.query(nonce, left_message, right_message);
    result <- None;
    if (ciphertext <> None) {
      result <- Some (publish mac_secret prefix (oget ciphertext));
    }
    return result;
  }
}.

module ConfidentialityReduction(A : PublishedAdversary, O : EncryptionOracle) = {
  module Adversary = A(CiphertextWrapper(O))

  proc distinguish() : bool = {
    var result : bool;
    CiphertextWrapper.mac_secret <$ dkey;
    result <@ Adversary.distinguish();
    return result;
  }
}.

section Reduction.
  declare module A <: PublishedAdversary {-PublishedRecordOracle, -CipherOracle, -CiphertextWrapper}.

  lemma record_confidentiality_reduction (challenge_bit : bool) &m :
    Pr[PublishedGame(A).main(challenge_bit) @ &m : res] =
    Pr[EncryptionGame(ConfidentialityReduction(A)).main(challenge_bit) @ &m : res].
  proof.
    byequiv => //=.
    proc; inline *; wp.
    call (_ : PublishedRecordOracle.secret{1} = CipherOracle.secret{2} /\
      PublishedRecordOracle.mac_secret{1} = CiphertextWrapper.mac_secret{2} /\
      PublishedRecordOracle.right{1} = CipherOracle.right{2} /\
      PublishedRecordOracle.seen{1} = CipherOracle.seen{2}).
    + proc; inline *; auto => />; smt().
    by wp; rnd; wp; rnd; auto.
  qed.

  (* A nonce-respecting primitive LR bound transfers to this reduction. The
     MAC needs no security assumption for this confidentiality statement. *)
  lemma record_confidentiality_gap &m :
    Pr[PublishedGame(A).main(true) @ &m : res] -
    Pr[PublishedGame(A).main(false) @ &m : res] =
    Pr[EncryptionGame(ConfidentialityReduction(A)).main(true) @ &m : res] -
    Pr[EncryptionGame(ConfidentialityReduction(A)).main(false) @ &m : res].
  proof. by rewrite !record_confidentiality_reduction. qed.

  lemma record_confidentiality_bound (epsilon : real) &m :
    `|Pr[EncryptionGame(ConfidentialityReduction(A)).main(true) @ &m : res] -
      Pr[EncryptionGame(ConfidentialityReduction(A)).main(false) @ &m : res]| <= epsilon =>
    `|Pr[PublishedGame(A).main(true) @ &m : res] -
      Pr[PublishedGame(A).main(false) @ &m : res]| <= epsilon.
  proof. by rewrite record_confidentiality_gap. qed.
end section Reduction.

(* Paranoid writes Serpent-CTR before XChaCha20 (pcv3crypto/stream.go).
   Independent prekey sampling is an unproved HKDF/provenance idealization.
   Only preservation of length is required of the preprocessor. *)
type preprocessing_key.
op dpreprocessing_key : preprocessing_key distr.
op preprocess : preprocessing_key -> bytes -> bytes -> bytes.
module type CascadedOracle = {
  proc query(prefix nonce iv left_message right_message : bytes) : (bytes * tag) option
}.
module type CascadedAdversary(O : CascadedOracle) = {
  proc distinguish() : bool
}.
module CascadedRecordOracle = {
  var secret : encryption_key
  var mac_secret : key
  var pre_secret : preprocessing_key
  var right : bool
  var seen : bytes list

  proc query(prefix nonce iv left_message right_message : bytes) : (bytes * tag) option = {
    var result : (bytes * tag) option;
    var ciphertext : bytes;
    result <- None;
    if (size iv = 16 /\ valid_query nonce left_message right_message seen) {
      seen <- nonce :: seen;
      ciphertext <- encrypt secret nonce
        (preprocess pre_secret iv (select right left_message right_message));
      result <- Some (publish mac_secret prefix ciphertext);
    }
    return result;
  }
}.
module CascadeGame(A : CascadedAdversary) = {
  module Adversary = A(CascadedRecordOracle)
  proc main(right : bool) : bool = {
    var result : bool;
    CascadedRecordOracle.secret <$ dencryption_key;
    CascadedRecordOracle.mac_secret <$ dkey;
    CascadedRecordOracle.pre_secret <$ dpreprocessing_key;
    CascadedRecordOracle.right <- right;
    CascadedRecordOracle.seen <- [];
    result <@ Adversary.distinguish();
    return result;
  }
}.
module CascadeWrapper(O : EncryptionOracle) = {
  var mac_secret : key
  var pre_secret : preprocessing_key
  proc query(prefix nonce iv left_message right_message : bytes) : (bytes * tag) option = {
    var ciphertext : bytes option;
    var result : (bytes * tag) option;
    result <- None;
    if (size iv = 16 /\ valid_query nonce left_message right_message []) {
      ciphertext <@ O.query(nonce, preprocess pre_secret iv left_message,
        preprocess pre_secret iv right_message);
      if (ciphertext <> None) {
        result <- Some (publish mac_secret prefix (oget ciphertext));
      }
    }
    return result;
  }
}.
module CascadeReduction(A : CascadedAdversary, O : EncryptionOracle) = {
  module Adversary = A(CascadeWrapper(O))
  proc distinguish() : bool = {
    var result : bool;
    CascadeWrapper.mac_secret <$ dkey;
    CascadeWrapper.pre_secret <$ dpreprocessing_key;
    result <@ Adversary.distinguish();
    return result;
  }
}.
section CascadeReduction.
  declare module C <: CascadedAdversary {-CascadedRecordOracle, -CascadeWrapper,
    -CipherOracle, -CiphertextWrapper, -PublishedRecordOracle}.

  lemma cascade_confidentiality_reduction (challenge_bit : bool) &m :
    (forall k iv message, size (preprocess k iv message) = size message) =>
    Pr[CascadeGame(C).main(challenge_bit) @ &m : res] =
    Pr[EncryptionGame(CascadeReduction(C)).main(challenge_bit) @ &m : res].
  proof.
    move=> length_preserving; byequiv => //=.
    proc; inline *; wp.
    call (_ : CascadedRecordOracle.secret{1} = CipherOracle.secret{2} /\
      CascadedRecordOracle.mac_secret{1} = CascadeWrapper.mac_secret{2} /\
      CascadedRecordOracle.pre_secret{1} = CascadeWrapper.pre_secret{2} /\
      CascadedRecordOracle.right{1} = CipherOracle.right{2} /\
      CascadedRecordOracle.seen{1} = CipherOracle.seen{2}).
    + proc; inline *; auto => />; rewrite /valid_query /select; smt().
    by wp; rnd; rnd; wp; rnd; auto.
  qed.

  lemma cascade_confidentiality_bound (epsilon : real) &m :
    (forall k iv message, size (preprocess k iv message) = size message) =>
    `|Pr[EncryptionGame(CascadeReduction(C)).main(true) @ &m : res] -
      Pr[EncryptionGame(CascadeReduction(C)).main(false) @ &m : res]| <= epsilon =>
    `|Pr[CascadeGame(C).main(true) @ &m : res] -
      Pr[CascadeGame(C).main(false) @ &m : res]| <= epsilon.
  proof.
    move=> length_preserving.
    have hright := cascade_confidentiality_reduction true &m length_preserving.
    have hleft := cascade_confidentiality_reduction false &m length_preserving.
    by rewrite hright hleft.
  qed.
end section CascadeReduction.

(* This covers ciphertext-only record postprocessing, including either exact
   prefix above. Go refinement, HKDF hybrids, key-correlated metadata, multiple
   sessions, XChaCha20 security, preprocessing length refinement, D1 bootstraps, password
   guessing, CCA, size hiding and deniability are not proved. *)
