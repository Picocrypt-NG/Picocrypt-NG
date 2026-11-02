require import AllCore List RecordFraming RecordIntegrity NormalStream.

lemma reordered_guard_control_rejected (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  !accepted_without_order secret partial_profile
    (sign_stream secret [partial_final; partial_data]).
proof.
  move=> correct.
  have attack := reordered_mutant_accepts secret correct.
  by done.
qed.
