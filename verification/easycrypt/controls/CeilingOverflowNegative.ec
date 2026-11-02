require import AllCore SafeCastRepresentation WordArithmetic.

lemma wrapped_ceiling_matches_mathematical_ceiling :
  unchecked_ceil max_uint64 2 = ceiling max_uint64 2.
proof.
  by rewrite /unchecked_ceil /ceiling /max_uint64 /uint64_modulus.
qed.
