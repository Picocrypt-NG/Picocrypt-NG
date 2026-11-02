require import AllCore NormalPhysicalEOF.

lemma byte_at_boundary_may_be_treated_as_exact :
  eof_policy true 0 one_byte_eof no_progress = (EOFExact, 1).
proof.
  by rewrite /eof_policy /classify /stopped_state /one_byte_eof /has_eof.
qed.
