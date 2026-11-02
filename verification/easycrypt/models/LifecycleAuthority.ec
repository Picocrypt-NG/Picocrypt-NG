require import AllCore List.

(* Model only: no Go, crypto-completion, filesystem or provider refinement.
   One effect consumes one operation-scoped deletion-authority capability;
   it does not count individual unlinks in a multi-file deletion manifest.
   CompleteWrite is a trusted producer interface event, not a crypto proof.
   Public snapshots and restored receipts cannot produce that event's origin. *)
type producer = [ WriteProducer | ReadProducer | ForceProducer
                | PresentationProducer | RestoredReceiptProducer ].
type publication = [ Unpublished | Durable | Uncertain ].
type event = [ CompleteWrite | CompleteRead | ObserveForce
             | ObservePresentation | RestoreReceipt | CommitDurable
             | CommitUncertain | OpenFollowup | SettleOwners | ConfirmCleanup
             | CleanupWarning | Cancel | OptIn | FinalizeWrite | UseDeletion ].

(* Phases: 0 selected, 1 trusted whole-write completion, 2 trusted durable commit,
   3 follow-up owners settled, 4 cleanup confirmed, 5 runner finalized.
   Reopening custody returns to phase 2. Warning/cancellation stays latched;
   it prevents later effects without pretending to undo an earlier effect. *)
type state = {
  origin : producer;
  phase : int;
  published : publication;
  revoked : bool;
  opted : bool;
  consumed : bool;
  effects : int;
}.

op initial (p : producer) : state = {|
  origin = p; phase = 0; published = Unpublished;
  revoked = false; opted = false; consumed = false; effects = 0;
|}.

(* Mutation control: ignoring this revocation must refute the theorem below. *)
op revoke_cleanup (s : state) : state = {| s with revoked = true |}.

op emits (s : state) : bool =
  s.`phase = 5 /\ s.`opted /\ !s.`revoked /\ !s.`consumed.

op step (s : state) (e : event) : state =
  with e = CompleteWrite =>
    if s.`origin = WriteProducer /\ s.`phase = 0
    then {| s with phase = 1 |} else s
  with e = CommitDurable =>
    if s.`phase = 1 /\ s.`published = Unpublished
    then {| s with phase = 2; published = Durable |} else s
  with e = CommitUncertain =>
    if s.`phase = 1 /\ s.`published = Unpublished
    then {| s with published = Uncertain |} else s
  with e = OpenFollowup =>
    if 2 <= s.`phase /\ !s.`consumed
    then {| s with phase = 2 |} else s
  with e = SettleOwners =>
    if s.`phase = 2 then {| s with phase = 3 |} else s
  with e = ConfirmCleanup =>
    if s.`phase = 3 then {| s with phase = 4 |} else s
  with e = FinalizeWrite =>
    if s.`phase = 4 /\ !s.`revoked /\ !s.`consumed
    then {| s with phase = 5 |} else s
  with e = CleanupWarning => revoke_cleanup s
  with e = Cancel => {| s with revoked = true |}
  with e = OptIn => {| s with opted = true |}
  with e = UseDeletion =>
    if emits s
    then {| s with consumed = true; effects = s.`effects + 1 |} else s
  with e = CompleteRead => s
  with e = ObserveForce => s
  with e = ObservePresentation => s
  with e = RestoreReceipt => s.

op run (p : producer) (trace : event list) : state =
  foldl step (initial p) trace.

op successful_prefix : event list =
  [CompleteWrite; CommitDurable; SettleOwners; ConfirmCleanup;
   FinalizeWrite; OptIn].

lemma successful_trace_is_live :
  emits (run WriteProducer successful_prefix).
proof. by rewrite /run /successful_prefix /initial /emits /=. qed.

lemma late_cleanup_revocation :
  (run WriteProducer (successful_prefix ++ [CleanupWarning; UseDeletion])).`effects = 0.
proof.
rewrite /run /successful_prefix /initial /= /emits /revoke_cleanup /=.
by done.
qed.

op history1 : event list = [CompleteWrite].
op history2 : event list = rcons history1 CommitDurable.
op history3 : event list = rcons history2 SettleOwners.
op history4 : event list = rcons history3 ConfirmCleanup.
op history5 : event list = rcons history4 FinalizeWrite.
op history6 : event list = rcons history5 UseDeletion.

op control_safe (s : state) : bool =
  0 <= s.`phase <= 5 /\
  (0 < s.`phase => s.`origin = WriteProducer) /\
  (2 <= s.`phase => s.`published = Durable) /\
  0 <= s.`effects <= 1 /\ (s.`consumed <=> s.`effects = 1) /\
  (s.`effects = 1 => s.`phase = 5).

op history_safe (trace : event list) (s : state) : bool =
  (1 <= s.`phase => subseq history1 trace) /\
  (2 <= s.`phase => subseq history2 trace) /\
  (3 <= s.`phase => subseq history3 trace) /\
  (4 <= s.`phase => subseq history4 trace) /\
  (5 <= s.`phase => subseq history5 trace) /\
  (s.`opted => OptIn \in trace) /\
  (s.`effects = 1 => subseq history6 trace).

lemma subseq_after_event (xs ys : event list) (e : event) :
  subseq xs ys => subseq xs (rcons ys e).
proof. by smt(subseq_trans subseq_rcons). qed.

lemma subseq_extend_event (xs ys : event list) (e : event) :
  subseq xs ys => subseq (rcons xs e) (rcons ys e).
proof.
move=> h; rewrite -!cats1.
by apply cat_subseq; [exact h | apply subseq_refl].
qed.

lemma initial_control_safe (p : producer) : control_safe (initial p).
proof. by rewrite /control_safe /initial /=. qed.

lemma step_control_safe (s : state) (e : event) :
  control_safe s => control_safe (step s e).
proof.
case: s => origin phase published revoked opted consumed effects.
case: e => /=.
+ rewrite /control_safe /=.
  case: (origin = WriteProducer /\ phase = 0) => /=; smt().
+ done.
+ done.
+ done.
+ done.
+ rewrite /control_safe /=.
  case: (phase = 1 /\ published = Unpublished) => /=; smt().
+ rewrite /control_safe /=.
  case: (phase = 1 /\ published = Unpublished) => /=; smt().
+ rewrite /control_safe /=.
  case: (2 <= phase /\ !consumed) => /=; smt().
+ rewrite /control_safe /=.
  case: (phase = 2) => /=; smt().
+ rewrite /control_safe /=.
  case: (phase = 3) => /=; smt().
+ by rewrite /control_safe /revoke_cleanup /=.
+ by rewrite /control_safe /=.
+ by rewrite /control_safe /=.
+ rewrite /control_safe /=.
  case: (phase = 4 /\ !revoked /\ !consumed) => /=; smt().
+ rewrite /control_safe /emits /=.
  case: (phase = 5 /\ opted /\ !revoked /\ !consumed) => /=; smt().
qed.

lemma run_control_safe (p : producer) (trace : event list) :
  control_safe (run p trace).
proof.
elim/last_ind: trace => [|trace e ih].
+ exact (initial_control_safe p).
+ rewrite /run foldl_rcons.
  by apply step_control_safe.
qed.

lemma initial_history_safe (p : producer) : history_safe [] (initial p).
proof. by rewrite /history_safe /initial /=. qed.

lemma history1_event (trace : event list) :
  subseq history1 (rcons trace CompleteWrite).
proof.
have h := subseq_extend_event [] trace CompleteWrite (sub0seq trace).
by rewrite /history1; exact h.
qed.

lemma history2_event (trace : event list) :
  subseq history1 trace => subseq history2 (rcons trace CommitDurable).
proof. by rewrite /history2; apply subseq_extend_event. qed.

lemma history3_event (trace : event list) :
  subseq history2 trace => subseq history3 (rcons trace SettleOwners).
proof. by rewrite /history3; apply subseq_extend_event. qed.

lemma history4_event (trace : event list) :
  subseq history3 trace => subseq history4 (rcons trace ConfirmCleanup).
proof. by rewrite /history4; apply subseq_extend_event. qed.

lemma history5_event (trace : event list) :
  subseq history4 trace => subseq history5 (rcons trace FinalizeWrite).
proof. by rewrite /history5; apply subseq_extend_event. qed.

lemma history6_event (trace : event list) :
  subseq history5 trace => subseq history6 (rcons trace UseDeletion).
proof. by rewrite /history6; apply subseq_extend_event. qed.

lemma step_history_safe (s : state) (e : event) (trace : event list) :
  control_safe s => history_safe trace s =>
  history_safe (rcons trace e) (step s e).
proof.
case: s => origin phase published revoked opted consumed effects.
case: e => /=.
+ rewrite /control_safe /history_safe /=.
  case: (origin = WriteProducer /\ phase = 0) => /=;
    smt(subseq_after_event mem_rcons history1_event).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=.
  case: (phase = 1 /\ published = Unpublished) => /=;
    smt(subseq_after_event mem_rcons history2_event).
+ rewrite /history_safe /=.
  case: (phase = 1 /\ published = Unpublished) => /=;
    smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=.
  case: (2 <= phase /\ !consumed) => /=;
    smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=.
  case: (phase = 2) => /=;
    smt(subseq_after_event mem_rcons history3_event).
+ rewrite /history_safe /=.
  case: (phase = 3) => /=;
    smt(subseq_after_event mem_rcons history4_event).
+ rewrite /history_safe /revoke_cleanup /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=; smt(subseq_after_event mem_rcons).
+ rewrite /history_safe /=.
  case: (phase = 4 /\ !revoked /\ !consumed) => /=;
    smt(subseq_after_event mem_rcons history5_event).
+ rewrite /history_safe /emits /=.
  case: (phase = 5 /\ opted /\ !revoked /\ !consumed) => /=;
    smt(subseq_after_event mem_rcons history6_event).
qed.

lemma run_history_safe (p : producer) (trace : event list) :
  history_safe trace (run p trace).
proof.
elim/last_ind: trace => [|trace e ih].
+ exact (initial_history_safe p).
+ rewrite /run foldl_rcons.
  by apply step_history_safe; [apply run_control_safe | exact ih].
qed.

lemma step_origin (s : state) (e : event) :
  (step s e).`origin = s.`origin.
proof. by case: e => //=; smt(). qed.

lemma run_origin (p : producer) (trace : event list) :
  (run p trace).`origin = p.
proof.
elim/last_ind: trace => [|trace e ih]; first by rewrite /run /initial /=.
by rewrite /run foldl_rcons step_origin.
qed.

lemma no_destructive_effect_without_earlier_events
  (p : producer) (trace : event list) :
  (run p trace).`effects < (step (run p trace) UseDeletion).`effects =>
  p = WriteProducer /\ subseq history5 trace /\ OptIn \in trace.
proof.
have hc := run_control_safe p trace.
have hh := run_history_safe p trace.
have ho := run_origin p trace.
case: (emits (run p trace)) => he /=; last by smt().
by move: hc hh he; rewrite /control_safe /history_safe /emits; smt().
qed.

lemma every_emitted_effect_has_ordered_history
  (p : producer) (trace : event list) :
  (run p trace).`effects = 1 =>
  p = WriteProducer /\ subseq history6 trace.
proof.
have hc := run_control_safe p trace.
have hh := run_history_safe p trace.
have ho := run_origin p trace.
by move: hc hh; rewrite /control_safe /history_safe; smt().
qed.

lemma no_read_force_presentation_or_receipt_authority
  (p : producer) (trace : event list) :
  p <> WriteProducer => (run p trace).`effects = 0.
proof.
have hc := run_control_safe p trace.
have ho := run_origin p trace.
by move: hc; rewrite /control_safe; smt().
qed.

lemma at_most_one_consumption (p : producer) (trace : event list) :
  0 <= (run p trace).`effects <= 1.
proof. have h := run_control_safe p trace; by move: h; rewrite /control_safe; smt(). qed.

lemma step_revoked_conserves (s : state) (e : event) :
  s.`revoked =>
  (step s e).`revoked /\ (step s e).`effects = s.`effects.
proof. by case: e => //=; smt(). qed.

lemma revoked_suffix_conserves (s : state) (suffix : event list) :
  s.`revoked =>
  (foldl step s suffix).`revoked /\
  (foldl step s suffix).`effects = s.`effects.
proof.
elim: suffix s => [|e suffix ih] s /=; first by smt().
by smt(step_revoked_conserves).
qed.

lemma cleanup_warning_blocks_all_later_effects
  (p : producer) (prefix suffix : event list) :
  (run p (prefix ++ CleanupWarning :: suffix)).`effects =
  (run p prefix).`effects.
proof.
rewrite /run foldl_cat /=.
have h := revoked_suffix_conserves (revoke_cleanup (run p prefix)) suffix.
by move: h; rewrite /revoke_cleanup /=; smt().
qed.

lemma cancellation_blocks_all_later_effects
  (p : producer) (prefix suffix : event list) :
  (run p (prefix ++ Cancel :: suffix)).`effects =
  (run p prefix).`effects.
proof.
rewrite /run foldl_cat /=.
have h := revoked_suffix_conserves (revoke_cleanup (run p prefix)) suffix.
by move: h; rewrite /revoke_cleanup /=; smt().
qed.

lemma uncertain_cannot_be_reclassified (s : state) (e : event) :
  s.`published = Uncertain => (step s e).`published = Uncertain.
proof. by case: e => //=; smt(). qed.

lemma uncertain_stays_uncertain (s : state) (suffix : event list) :
  s.`published = Uncertain =>
  (foldl step s suffix).`published = Uncertain.
proof.
elim: suffix s => [|e suffix ih] s /=; first by smt().
by smt(uncertain_cannot_be_reclassified).
qed.

lemma uncertain_publication_has_no_later_authority
  (p : producer) (prefix suffix : event list) :
  (run p prefix).`published = Uncertain =>
  !emits (run p (prefix ++ suffix)).
proof.
have hp := uncertain_stays_uncertain (run p prefix) suffix.
have hc := run_control_safe p (prefix ++ suffix).
move: hc hp.
rewrite /control_safe /emits /run foldl_cat.
by smt().
qed.

lemma reopened_followup_revokes_current_eligibility (s : state) :
  !emits (step s OpenFollowup).
proof.
case: s => origin phase published revoked opted consumed effects.
rewrite /emits /=.
case: (2 <= phase /\ !consumed) => /=; smt().
qed.

lemma observation_and_restoration_are_authority_free (s : state) :
  step s CompleteRead = s /\ step s ObserveForce = s /\
  step s ObservePresentation = s /\ step s RestoreReceipt = s.
proof. done. qed.

lemma successful_trace_consumes_once :
  (run WriteProducer (successful_prefix ++ [UseDeletion; UseDeletion])).`effects = 1.
proof. rewrite /run /successful_prefix /initial /=; by smt(). qed.

lemma cancelled_successful_trace_has_no_effect :
  (run WriteProducer (successful_prefix ++ [Cancel; UseDeletion])).`effects = 0.
proof. rewrite /run /successful_prefix /initial /=; by smt(). qed.
