require import AllCore PayloadGeometry WordArithmetic.

lemma partial_rs_body_uses_floor_rounding : encoded_body_length true 65 = 136.
proof.
  by rewrite /encoded_body_length /semantic_body_length /ceiling.
qed.
