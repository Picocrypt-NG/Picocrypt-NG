require import AllCore.

lemma integer_order_smoke (n : int) : 0 <= n => 0 < n + 1.
proof. by smt(). qed.
