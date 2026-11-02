require import AllCore List RecordFraming CorePolicy.

lemma changed_core_magic_is_accepted :
  concrete_core_policy (policy_fixture 3 0 (List.map byte_of_int [80; 67; 86; 1])).
proof.
  by rewrite wrong_magic_control.
qed.
