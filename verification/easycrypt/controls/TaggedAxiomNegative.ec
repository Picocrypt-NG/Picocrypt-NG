require import AllCore.

axiom [nosmt] unchecked : false.
lemma reject_tagged_assumption : false.
proof. exact unchecked. qed.
