require import AllCore PayloadGeometry.

lemma empty_plaintext_has_no_payload_records : payload_length 0 false = 0.
proof.
  by rewrite empty_payload_has_final.
qed.
