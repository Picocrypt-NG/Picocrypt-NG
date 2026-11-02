require import AllCore SafeCastRepresentation WordArithmetic.

lemma refused_addition_must_return_zero :
  (checked_add max_uint64 2).`1 = 0.
proof.
  by rewrite refused_add_is_not_always_zero.
qed.
