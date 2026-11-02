require import AllCore List RecordFraming RecordIntegrity NormalStream.

lemma dropped_final_guard_control_rejected (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  !accepted_without_shape secret partial_profile
    (sign_stream secret [partial_data]).
proof.
  move=> correct.
  have attack := dropped_final_mutant_accepts secret correct.
  by done.
qed.
