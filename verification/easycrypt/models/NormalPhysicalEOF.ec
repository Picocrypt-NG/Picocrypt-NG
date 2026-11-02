require import AllCore.

type eof_state = [ EOFExact | EOFFailure | EOFOperation ].
type decision = [ StopExact | StopFailure | StopOperation | Retry ].
type observation = {
  eo_count : int;
  eo_is_eof : bool;
  eo_is_unexpected_eof : bool;
  eo_error_nil : bool
}.

(* Match flags denote returned errors.Is observations. Their realization by
   actual error objects, termination and panic behavior are separate. *)
op error_observation_valid (o : observation) : bool =
  o.`eo_error_nil => !o.`eo_is_eof /\ !o.`eo_is_unexpected_eof.
op has_eof (o : observation) : bool = o.`eo_is_eof \/ o.`eo_is_unexpected_eof.
op exact_observation (o : observation) : bool = o.`eo_count = 0 /\ has_eof o.
op retry_observation (o : observation) : bool =
  o.`eo_count = 0 /\ !has_eof o /\ o.`eo_error_nil.

op classify (o : observation) : decision =
  if o.`eo_count < 0 \/ 1 < o.`eo_count then StopOperation
  else if o.`eo_count <> 0 then StopFailure
  else if has_eof o then StopExact
  else if !o.`eo_error_nil then StopOperation
  else Retry.
op stopped_state (d : decision) : eof_state =
  match d with
  | StopExact => EOFExact
  | StopFailure => EOFFailure
  | StopOperation => EOFOperation
  | Retry => EOFOperation
  end.

(* Exactly the source's two ReadAt attempts. A retry from the obs2 observation
   is exhausted; the function returns Operation rather than reading again. *)
op eof_policy source_present offset (obs1 obs2 : observation) : eof_state * int =
  if !source_present \/ offset < 0 then (EOFOperation, 0)
  else if classify obs1 = Retry then (stopped_state (classify obs2), 2)
  else (stopped_state (classify obs1), 1).

lemma classify_exact o : (classify o = StopExact) = exact_observation o.
proof. rewrite /classify /exact_observation /has_eof; smt(). qed.

lemma classify_failure o : (classify o = StopFailure) = (o.`eo_count = 1).
proof. rewrite /classify /has_eof; smt(). qed.

lemma classify_retry o : (classify o = Retry) = retry_observation o.
proof. rewrite /classify /retry_observation /has_eof; smt(). qed.

lemma malformed_count_stops o :
  o.`eo_count < 0 \/ 1 < o.`eo_count => classify o = StopOperation.
proof. by rewrite /classify => ->. qed.

lemma one_byte_precedes_error_flags o :
  o.`eo_count = 1 => classify o = StopFailure.
proof. by rewrite /classify => ->. qed.

lemma nil_error_cannot_supply_eof o :
  error_observation_valid o => o.`eo_error_nil => !has_eof o.
proof. rewrite /error_observation_valid /has_eof; smt(). qed.

lemma guarded_no_io present offset obs1 obs2 :
  !present \/ offset < 0 => eof_policy present offset obs1 obs2 = (EOFOperation, 0).
proof. by rewrite /eof_policy => ->. qed.

lemma read_count_bound present offset obs1 obs2 :
  0 <= (eof_policy present offset obs1 obs2).`2 <= 2 /\
  (present /\ 0 <= offset => 1 <= (eof_policy present offset obs1 obs2).`2).
proof. rewrite /eof_policy; smt(). qed.

lemma stopped_exact d : (stopped_state d = EOFExact) = (d = StopExact).
proof. by case: d; rewrite /stopped_state. qed.

lemma stopped_failure d : (stopped_state d = EOFFailure) = (d = StopFailure).
proof. by case: d; rewrite /stopped_state. qed.

lemma exact_characterization present offset obs1 obs2 :
  ((eof_policy present offset obs1 obs2).`1 = EOFExact) =
  (present /\ 0 <= offset /\
    (exact_observation obs1 \/ (retry_observation obs1 /\ exact_observation obs2))).
proof.
  rewrite /eof_policy.
  have hf := classify_exact obs1.
  have hs := classify_exact obs2.
  have hr := classify_retry obs1.
  have h1 := stopped_exact (classify obs1).
  have h2 := stopped_exact (classify obs2).
  smt().
qed.

lemma failure_characterization present offset obs1 obs2 :
  ((eof_policy present offset obs1 obs2).`1 = EOFFailure) =
  (present /\ 0 <= offset /\
    (obs1.`eo_count = 1 \/ (retry_observation obs1 /\ obs2.`eo_count = 1))).
proof.
  rewrite /eof_policy.
  have hf := classify_failure obs1.
  have hs := classify_failure obs2.
  have hr := classify_retry obs1.
  have h1 := stopped_failure (classify obs1).
  have h2 := stopped_failure (classify obs2).
  smt().
qed.

lemma retry_twice_exhausted obs1 obs2 offset :
  0 <= offset => retry_observation obs1 => retry_observation obs2 =>
  eof_policy true offset obs1 obs2 = (EOFOperation, 2).
proof.
  move=> ho hf hs.
  have hfirst : classify obs1 = Retry by rewrite classify_retry.
  have hsecond : classify obs2 = Retry by rewrite classify_retry.
  by rewrite /eof_policy hfirst hsecond /stopped_state /=; smt().
qed.

lemma one_byte_is_failure obs1 obs2 offset :
  0 <= offset => obs1.`eo_count = 1 =>
  eof_policy true offset obs1 obs2 = (EOFFailure, 1).
proof.
  move=> ho hc.
  have h := one_byte_precedes_error_flags obs1 hc.
  by rewrite /eof_policy h /stopped_state /=; smt().
qed.

op no_progress : observation = {|
  eo_count = 0; eo_is_eof = false; eo_is_unexpected_eof = false; eo_error_nil = true
|}.
op one_byte_eof : observation = {|
  eo_count = 1; eo_is_eof = true; eo_is_unexpected_eof = false; eo_error_nil = false
|}.

lemma appended_byte_counterexample :
  error_observation_valid one_byte_eof /\
  eof_policy true 0 one_byte_eof no_progress = (EOFFailure, 1).
proof. by rewrite /error_observation_valid /eof_policy /classify /stopped_state /one_byte_eof /no_progress /has_eof. qed.

(* The intentionally defective ordering checks EOF before the nonzero count. *)
op classify_wrong_order (o : observation) : decision =
  if o.`eo_count < 0 \/ 1 < o.`eo_count then StopOperation
  else if has_eof o then StopExact
  else if o.`eo_count <> 0 then StopFailure
  else if !o.`eo_error_nil then StopOperation
  else Retry.

lemma wrong_order_accepts_appended_byte :
  classify_wrong_order one_byte_eof = StopExact /\ classify one_byte_eof = StopFailure.
proof. by rewrite /classify_wrong_order /classify /one_byte_eof /has_eof. qed.

type tail_gate = [ TailAuthFailure | TailOperationFailure | TailEligible ].
op caller_tail_gate suffix_equal size_equal eof : tail_gate =
  if !suffix_equal \/ !size_equal \/ eof = EOFFailure then TailAuthFailure
  else if eof = EOFOperation then TailOperationFailure
  else TailEligible.

lemma caller_gate_eligible suffix_equal size_equal eof :
  (caller_tail_gate suffix_equal size_equal eof = TailEligible) =
  (suffix_equal /\ size_equal /\ eof = EOFExact).
proof. case: eof; rewrite /caller_tail_gate; smt(). qed.

lemma exact_observation_does_not_override_suffix :
  caller_tail_gate false true EOFExact = TailAuthFailure.
proof. by rewrite /caller_tail_gate. qed.
