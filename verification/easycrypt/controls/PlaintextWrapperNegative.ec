require import AllCore List Distr RecordFraming RecordConfidentiality.

(* Defect: a published wrapper retains its input plaintext beside ciphertext. *)
module PlaintextLeak = {
  proc main(right : bool, ciphertext : bytes) : bool = {
    var published : bytes * bytes;
    published <- (ciphertext, select right [byte_of_int 0] [byte_of_int 1]);
    return published.`2 = [byte_of_int 1];
  }
}.

lemma leaking_wrapper_left ciphertext &m :
  Pr[PlaintextLeak.main(false, ciphertext) @ &m : res] = 0%r.
proof.
  byphoare (_ : right = false ==> res) => //.
  hoare; proc; auto => />.
  by rewrite /select /=; smt(byte_zero_one).
qed.

lemma leaking_wrapper_right ciphertext &m :
  Pr[PlaintextLeak.main(true, ciphertext) @ &m : res] = 1%r.
proof. byphoare (_ : right = true ==> res) => //; proc; auto; rewrite /select. qed.

lemma plaintext_wrapper_preserves_confidentiality ciphertext &m :
  Pr[PlaintextLeak.main(false, ciphertext) @ &m : res] =
  Pr[PlaintextLeak.main(true, ciphertext) @ &m : res].
proof.
  by rewrite leaking_wrapper_left leaking_wrapper_right.
qed.
