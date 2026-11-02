require import AllCore List RecordFraming RecordIntegrity NormalStream.

lemma extra_record_guard_control_rejected (secret : key) :
  (forall message, verify secret message (mac secret message)) =>
  !accepted_without_shape secret partial_profile
    (sign_stream secret [partial_data; partial_final; partial_final]).
proof.
  move=> correct.
  have attack := extra_record_mutant_accepts secret correct.
  by done.
qed.
