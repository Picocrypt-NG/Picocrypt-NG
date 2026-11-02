require import AllCore CorePolicy.

lemma unknown_core_feature_is_accepted :
  concrete_core_policy (policy_fixture 3 4 normal_magic).
proof.
  by rewrite /concrete_core_policy /policy_fixture.
qed.
