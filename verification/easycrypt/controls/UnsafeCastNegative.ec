require import AllCore SafeCastRepresentation.

lemma guard_disabled_cast_must_refuse (value : int) :
  value = max_int64 + 1 => guard_disabled_model value = (0, false).
proof.
  move=> ->.
  by rewrite /guard_disabled_model /go_signed /max_int64 /uint64_modulus.
qed.
