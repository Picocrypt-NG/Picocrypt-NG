require import AllCore List RecordFraming CredentialContext.

lemma omitted_role_preserves_front_tail_separation :
  role_omission NormalSchedule 1 0 [] <> role_omission NormalSchedule 1 1 [].
proof.
  by rewrite omitted_role_alias.
qed.
