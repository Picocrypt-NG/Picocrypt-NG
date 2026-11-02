require import AllCore List.

(* Interface policy only. VerifyPayload, VerifyFinal and CloseTail stand for
   successful reader checks; their cryptographic and Go implementations are
   separate obligations. Recovery events accept an already validated immutable
   recovery tuple. Publication events report a transport result, not an effect
   proved here. This model does not grant any source-deletion authority.
   The callback path assumes successful native output preparation. Failures in
   that preparation can replace reader success with OperationFailed in Go and
   are outside the result-preserving events below. *)
type origin = [ OrdinaryReader | ForceReader | WriteProducer
              | PresentationProducer | RestoredReceiptProducer ].
type result = [ Pending | Healthy | Degraded | ForceVerified
              | ForcePartial | ForceUnverified | RawSelected ].
type payload = [ RawPayload | ArchivePayload ].
type publication = [ NotPublished | PublishedDurable
                   | PublishedUncertain | PublicationIndeterminate ].
type event = [ VerifyPayload | VerifyFinal | CloseTail
             | CompleteHealthy | CompleteDegraded
             | RecoverVerified | RecoverPartial | RecoverUnverified | RecoverRawSelected
             | ObserveInnerAuthentication | EnterCallback | UsePublish | UseArchive
             | ReturnCallback | RecordPublication of publication ].

type state = {
  producer : origin;
  kind : payload;
  phase : int;
  outcome : result;
  entered : bool;
  active : bool;
  consumed : bool;
  revoked : bool;
  publish_actions : int;
  archive_actions : int;
  publication_attempted : bool;
  published : publication;
}.

op initial (p : origin) (k : payload) : state = {|
  producer = p; kind = k; phase = 0; outcome = Pending;
  entered = false; active = false; consumed = false; revoked = false;
  publish_actions = 0; archive_actions = 0;
  publication_attempted = false; published = NotPublished;
|}.

op ordinary_complete (s : state) : bool =
  s.`outcome = Healthy \/ s.`outcome = Degraded.
op force_result (r : result) : bool =
  r = ForceVerified \/ r = ForcePartial \/ r = ForceUnverified \/ r = RawSelected.

(* A reusable completion predicate is distinct from a consuming output action.
   Degraded ordinary reads and verified Force recovery may publish raw bytes;
   only exact ordinary success can carry archive authority. ArchivePayload also
   abstracts a raw ZIP whose separate authenticated preparation has succeeded. *)
op authenticated_completion (s : state) : bool =
  s.`producer = OrdinaryReader /\ s.`outcome = Healthy.
op archive_eligible (s : state) : bool =
  authenticated_completion s /\ s.`kind = ArchivePayload.
op callback_live (s : state) : bool =
  s.`active /\ !s.`consumed /\ !s.`revoked.
op source_deletion_allowed (s : state) : bool = false.

op recover (s : state) (r : result) : state =
  if s.`producer = ForceReader /\ s.`outcome = Pending
  then {| s with outcome = r |} else s.

op step (s : state) (e : event) : state =
  with e = VerifyPayload =>
    if s.`producer = OrdinaryReader /\ s.`phase = 0 /\ s.`outcome = Pending
    then {| s with phase = 1 |} else s
  with e = VerifyFinal =>
    if s.`phase = 1 then {| s with phase = 2 |} else s
  with e = CloseTail =>
    if s.`phase = 2 then {| s with phase = 3 |} else s
  with e = CompleteHealthy =>
    if s.`phase = 3 /\ s.`outcome = Pending
    then {| s with outcome = Healthy |} else s
  with e = CompleteDegraded =>
    if s.`phase = 3 /\ s.`outcome = Pending
    then {| s with outcome = Degraded |} else s
  with e = RecoverVerified => recover s ForceVerified
  with e = RecoverPartial => recover s ForcePartial
  with e = RecoverUnverified => recover s ForceUnverified
  with e = RecoverRawSelected => recover s RawSelected
  with e = ObserveInnerAuthentication => s
  with e = EnterCallback =>
    if ordinary_complete s /\ !s.`entered /\ !s.`revoked
    then {| s with entered = true; active = true |} else s
  with e = UsePublish =>
    if callback_live s /\ !archive_eligible s
    then {| s with consumed = true; publish_actions = s.`publish_actions + 1 |} else s
  with e = UseArchive =>
    if callback_live s /\ archive_eligible s
    then {| s with consumed = true; archive_actions = s.`archive_actions + 1 |} else s
  with e = ReturnCallback => {| s with active = false; revoked = true |}
  with e = RecordPublication p =>
    if !s.`publication_attempted /\
       (s.`publish_actions = 1 \/ force_result s.`outcome)
    then {| s with publication_attempted = true; published = p |} else s.

op run (p : origin) (k : payload) (trace : event list) : state =
  foldl step (initial p k) trace.

op payload_history : event list = [VerifyPayload].
op final_history : event list = rcons payload_history VerifyFinal.
op closed_history : event list = rcons final_history CloseTail.
op healthy_history : event list = rcons closed_history CompleteHealthy.
op degraded_history : event list = rcons closed_history CompleteDegraded.
op healthy_callback : event list = rcons healthy_history EnterCallback.
op degraded_callback : event list = rcons degraded_history EnterCallback.
op archive_history : event list = rcons healthy_callback UseArchive.
op healthy_publish_history : event list = rcons healthy_callback UsePublish.
op degraded_publish_history : event list = rcons degraded_callback UsePublish.

op control_safe (s : state) : bool =
  0 <= s.`phase <= 3 /\
  (0 < s.`phase => s.`producer = OrdinaryReader) /\
  (ordinary_complete s => s.`producer = OrdinaryReader /\ s.`phase = 3) /\
  (force_result s.`outcome => s.`producer = ForceReader /\ s.`phase = 0) /\
  (s.`entered => ordinary_complete s) /\
  (s.`active => s.`entered /\ !s.`revoked) /\
  0 <= s.`publish_actions /\ 0 <= s.`archive_actions /\
  s.`publish_actions + s.`archive_actions <= 1 /\
  (s.`consumed <=> s.`publish_actions + s.`archive_actions = 1) /\
  (s.`archive_actions = 1 => authenticated_completion s /\ s.`kind = ArchivePayload) /\
  (s.`publish_actions = 1 => ordinary_complete s) /\
  (s.`publication_attempted => s.`publish_actions = 1 \/ force_result s.`outcome).

op history_safe (trace : event list) (s : state) : bool =
  (1 <= s.`phase => subseq payload_history trace) /\
  (2 <= s.`phase => subseq final_history trace) /\
  (3 <= s.`phase => subseq closed_history trace) /\
  (s.`outcome = Healthy => subseq healthy_history trace) /\
  (s.`outcome = Degraded => subseq degraded_history trace) /\
  (s.`entered /\ s.`outcome = Healthy => subseq healthy_callback trace) /\
  (s.`entered /\ s.`outcome = Degraded => subseq degraded_callback trace) /\
  (s.`archive_actions = 1 => subseq archive_history trace) /\
  (s.`publish_actions = 1 =>
    subseq healthy_publish_history trace \/ subseq degraded_publish_history trace).

lemma subseq_after (xs ys : event list) (e : event) :
  subseq xs ys => subseq xs (rcons ys e).
proof. by smt(subseq_trans subseq_rcons). qed.

lemma subseq_extend (xs ys : event list) (e : event) :
  subseq xs ys => subseq (rcons xs e) (rcons ys e).
proof.
move=> h; rewrite -!cats1.
by apply cat_subseq; [exact h | apply subseq_refl].
qed.

lemma initial_safe (p : origin) (k : payload) :
  control_safe (initial p k) /\ history_safe [] (initial p k).
proof. by rewrite /control_safe /history_safe /initial /ordinary_complete /force_result /=. qed.

lemma payload_event (trace : event list) : subseq payload_history (rcons trace VerifyPayload).
proof.
have h := subseq_extend [] trace VerifyPayload (sub0seq trace).
by rewrite /payload_history; exact h.
qed.

lemma final_event (trace : event list) :
  subseq payload_history trace => subseq final_history (rcons trace VerifyFinal).
proof. by rewrite /final_history; apply subseq_extend. qed.

lemma closed_event (trace : event list) :
  subseq final_history trace => subseq closed_history (rcons trace CloseTail).
proof. by rewrite /closed_history; apply subseq_extend. qed.

lemma healthy_event (trace : event list) :
  subseq closed_history trace => subseq healthy_history (rcons trace CompleteHealthy).
proof. by rewrite /healthy_history; apply subseq_extend. qed.

lemma degraded_event (trace : event list) :
  subseq closed_history trace => subseq degraded_history (rcons trace CompleteDegraded).
proof. by rewrite /degraded_history; apply subseq_extend. qed.

lemma healthy_callback_event (trace : event list) :
  subseq healthy_history trace => subseq healthy_callback (rcons trace EnterCallback).
proof. by rewrite /healthy_callback; apply subseq_extend. qed.

lemma degraded_callback_event (trace : event list) :
  subseq degraded_history trace => subseq degraded_callback (rcons trace EnterCallback).
proof. by rewrite /degraded_callback; apply subseq_extend. qed.

lemma archive_event (trace : event list) :
  subseq healthy_callback trace => subseq archive_history (rcons trace UseArchive).
proof. by rewrite /archive_history; apply subseq_extend. qed.

lemma healthy_publish_event (trace : event list) :
  subseq healthy_callback trace => subseq healthy_publish_history (rcons trace UsePublish).
proof. by rewrite /healthy_publish_history; apply subseq_extend. qed.

lemma degraded_publish_event (trace : event list) :
  subseq degraded_callback trace => subseq degraded_publish_history (rcons trace UsePublish).
proof. by rewrite /degraded_publish_history; apply subseq_extend. qed.

lemma step_control_safe (s : state) (e : event) :
  control_safe s => control_safe (step s e).
proof.
case: s => producer kind phase outcome entered active consumed revoked pubs archives attempted published.
case: e => [||||||||||||||p] /=.
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = OrdinaryReader /\ phase = 0 /\ outcome = Pending) => /=; smt().
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 1) => /=; smt().
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 2) => /=; smt().
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 3 /\ outcome = Pending) => /=; smt().
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 3 /\ outcome = Pending) => /=; smt().
+ rewrite /recover /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt().
+ rewrite /recover /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt().
+ rewrite /recover /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt().
+ rewrite /recover /control_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt().
+ done.
+ rewrite /ordinary_complete /control_safe /force_result /authenticated_completion /=.
  case: ((outcome = Healthy \/ outcome = Degraded) /\ !entered /\ !revoked) => /=; smt().
+ rewrite /callback_live /archive_eligible /authenticated_completion
          /control_safe /ordinary_complete /force_result /=.
  case: ((active /\ !consumed /\ !revoked) /\
         !((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)) => /=; smt().
+ rewrite /callback_live /archive_eligible /authenticated_completion
          /control_safe /ordinary_complete /force_result /=.
  case: ((active /\ !consumed /\ !revoked) /\
         ((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)) => /=; smt().
+ rewrite /control_safe /ordinary_complete /force_result /authenticated_completion /=; smt().
+ rewrite /force_result /control_safe /ordinary_complete /authenticated_completion /=.
  case: (!attempted /\ (pubs = 1 \/
    (outcome = ForceVerified \/ outcome = ForcePartial \/ outcome = ForceUnverified \/ outcome = RawSelected))) => /=; smt().
qed.

lemma step_history_safe (s : state) (e : event) (trace : event list) :
  control_safe s => history_safe trace s => history_safe (rcons trace e) (step s e).
proof.
case: s => producer kind phase outcome entered active consumed revoked pubs archives attempted published.
case: e => [||||||||||||||p] /=.
+ rewrite /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = OrdinaryReader /\ phase = 0 /\ outcome = Pending) => /=;
    smt(subseq_after payload_event).
+ rewrite /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 1) => /=; smt(subseq_after final_event).
+ rewrite /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 2) => /=; smt(subseq_after closed_event).
+ rewrite /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 3 /\ outcome = Pending) => /=; smt(subseq_after healthy_event).
+ rewrite /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (phase = 3 /\ outcome = Pending) => /=; smt(subseq_after degraded_event).
+ rewrite /recover /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt(subseq_after).
+ rewrite /recover /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt(subseq_after).
+ rewrite /recover /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt(subseq_after).
+ rewrite /recover /control_safe /history_safe /ordinary_complete /force_result /authenticated_completion /=.
  case: (producer = ForceReader /\ outcome = Pending) => /=; smt(subseq_after).
+ rewrite /history_safe /=; smt(subseq_after).
+ rewrite /ordinary_complete /control_safe /history_safe /force_result /authenticated_completion /=.
  case: ((outcome = Healthy \/ outcome = Degraded) /\ !entered /\ !revoked) => /=;
    smt(subseq_after healthy_callback_event degraded_callback_event).
+ rewrite /callback_live /archive_eligible /authenticated_completion
          /control_safe /history_safe /ordinary_complete /force_result /=.
  case: ((active /\ !consumed /\ !revoked) /\
         !((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)) => /=;
    smt(subseq_after healthy_publish_event degraded_publish_event).
+ rewrite /callback_live /archive_eligible /authenticated_completion
          /control_safe /history_safe /ordinary_complete /force_result /=.
  case: ((active /\ !consumed /\ !revoked) /\
         ((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)) => /=;
    smt(subseq_after archive_event).
+ rewrite /history_safe /=; smt(subseq_after).
+ rewrite /force_result /history_safe /=.
  case: (!attempted /\ (pubs = 1 \/
    (outcome = ForceVerified \/ outcome = ForcePartial \/ outcome = ForceUnverified \/ outcome = RawSelected))) => /=;
    smt(subseq_after).
qed.

lemma run_safe (p : origin) (k : payload) (trace : event list) :
  control_safe (run p k trace) /\ history_safe trace (run p k trace).
proof.
elim/last_ind: trace => [|trace e ih].
+ exact (initial_safe p k).
+ rewrite /run foldl_rcons.
  by smt(step_control_safe step_history_safe).
qed.

lemma origin_is_preserved (s : state) (e : event) :
  (step s e).`producer = s.`producer.
proof. by case: e => //=; rewrite /recover; smt(). qed.

lemma run_origin (p : origin) (k : payload) (trace : event list) :
  (run p k trace).`producer = p.
proof.
elim/last_ind: trace => [|trace e ih]; first by rewrite /run /initial /=.
by rewrite /run foldl_rcons origin_is_preserved.
qed.

lemma archive_action_has_exact_read_history (p : origin) (k : payload) (trace : event list) :
  (run p k trace).`archive_actions = 1 =>
  p = OrdinaryReader /\ authenticated_completion (run p k trace) /\
  subseq archive_history trace.
proof.
have hs := run_safe p k trace; have ho := run_origin p k trace.
by move: hs; rewrite /control_safe /history_safe /authenticated_completion; smt().
qed.

lemma ordinary_completion_has_full_check_history (p : origin) (k : payload) (trace : event list) :
  ordinary_complete (run p k trace) =>
  p = OrdinaryReader /\ subseq closed_history trace.
proof.
have hs := run_safe p k trace; have ho := run_origin p k trace.
by move: hs; rewrite /control_safe /history_safe; smt().
qed.

lemma no_write_display_or_receipt_read_authority (p : origin) (k : payload) (trace : event list) :
  p <> OrdinaryReader =>
  !authenticated_completion (run p k trace) /\
  (run p k trace).`archive_actions = 0 /\ (run p k trace).`publish_actions = 0.
proof.
have hs := run_safe p k trace; have ho := run_origin p k trace.
by move: hs; rewrite /control_safe /ordinary_complete /authenticated_completion; smt().
qed.

lemma callback_actions_are_one_shot (p : origin) (k : payload) (trace : event list) :
  0 <= (run p k trace).`publish_actions + (run p k trace).`archive_actions <= 1.
proof. have hs := run_safe p k trace; by move: hs; rewrite /control_safe; smt(). qed.

lemma step_revoked_conserves (s : state) (e : event) :
  s.`revoked => (step s e).`revoked /\
  (step s e).`publish_actions = s.`publish_actions /\
  (step s e).`archive_actions = s.`archive_actions.
proof.
case: s => producer kind phase outcome entered active consumed revoked pubs archives attempted published.
move=> hr; case: e => [||||||||||||||p] /=.
+ by case: (producer = OrdinaryReader /\ phase = 0 /\ outcome = Pending).
+ by case: (phase = 1).
+ by case: (phase = 2).
+ by case: (phase = 3 /\ outcome = Pending).
+ by case: (phase = 3 /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ done.
+ rewrite /ordinary_complete /=.
  by case: ((outcome = Healthy \/ outcome = Degraded) /\ !entered /\ !revoked).
+ by rewrite /callback_live hr /=.
+ by rewrite /callback_live hr /=.
+ done.
+ by case: (!attempted /\ (pubs = 1 \/ force_result outcome)).
qed.

lemma returned_callback_never_acts_again (s : state) (suffix : event list) :
  s.`revoked =>
  (foldl step s suffix).`publish_actions = s.`publish_actions /\
  (foldl step s suffix).`archive_actions = s.`archive_actions /\
  (foldl step s suffix).`revoked.
proof.
elim: suffix s => [|e suffix ih] s /=; first by smt().
by smt(step_revoked_conserves).
qed.

lemma publication_does_not_upgrade_trust (s : state) (p : publication) :
  (step s (RecordPublication p)).`outcome = s.`outcome /\
  authenticated_completion (step s (RecordPublication p)) = authenticated_completion s.
proof. by rewrite /authenticated_completion /=; try rewrite !fun_if /=; smt(). qed.

lemma completed_result_is_immutable (s : state) (e : event) :
  s.`outcome <> Pending => (step s e).`outcome = s.`outcome.
proof. by case: e => //=; rewrite /recover; try rewrite !fun_if /=; smt(). qed.

lemma completed_result_survives_every_later_event (s : state) (suffix : event list) :
  s.`outcome <> Pending => (foldl step s suffix).`outcome = s.`outcome.
proof.
elim: suffix s => [|e suffix ih] s /=; first by smt().
by smt(completed_result_is_immutable).
qed.

lemma recorded_publication_is_immutable (s : state) (e : event) :
  s.`publication_attempted =>
  (step s e).`publication_attempted /\ (step s e).`published = s.`published.
proof.
case: s => producer kind phase outcome entered active consumed revoked pubs archives attempted published.
move=> ha; case: e => [||||||||||||||p] /=.
+ by case: (producer = OrdinaryReader /\ phase = 0 /\ outcome = Pending).
+ by case: (phase = 1).
+ by case: (phase = 2).
+ by case: (phase = 3 /\ outcome = Pending).
+ by case: (phase = 3 /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ rewrite /recover /=; by case: (producer = ForceReader /\ outcome = Pending).
+ done.
+ rewrite /ordinary_complete /=.
  by case: ((outcome = Healthy \/ outcome = Degraded) /\ !entered /\ !revoked).
+ rewrite /callback_live /archive_eligible /authenticated_completion /=.
  by case: ((active /\ !consumed /\ !revoked) /\
    !((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)).
+ rewrite /callback_live /archive_eligible /authenticated_completion /=.
  by case: ((active /\ !consumed /\ !revoked) /\
    ((producer = OrdinaryReader /\ outcome = Healthy) /\ kind = ArchivePayload)).
+ done.
+ by case: (!attempted /\ (pubs = 1 \/ force_result outcome)) => /=; smt().
qed.

lemma non_durable_publication_cannot_be_laundered (s : state) (suffix : event list) :
  s.`publication_attempted =>
  (foldl step s suffix).`publication_attempted /\
  (foldl step s suffix).`published = s.`published.
proof.
elim: suffix s => [|e suffix ih] s /=; first by smt().
by smt(recorded_publication_is_immutable).
qed.

lemma raw_selection_ignores_inner_success_and_publication (k : payload) (p : publication) :
  let s = run ForceReader k
    [RecoverRawSelected; ObserveInnerAuthentication; RecordPublication p] in
  s.`outcome = RawSelected /\ !authenticated_completion s /\
  s.`archive_actions = 0 /\ !source_deletion_allowed s.
proof. by rewrite /run /initial /= /recover /= /force_result /= /authenticated_completion /source_deletion_allowed /=. qed.

op checked_prefix : event list = [VerifyPayload; VerifyFinal; CloseTail].

lemma healthy_archive_is_nonvacuous :
  let s = run OrdinaryReader ArchivePayload
    (checked_prefix ++ [CompleteHealthy; EnterCallback; UseArchive; UseArchive; ReturnCallback]) in
  authenticated_completion s /\ s.`archive_actions = 1 /\ !callback_live s.
proof.
rewrite /run /checked_prefix /initial /= /ordinary_complete /=.
by do 3! rewrite /callback_live /archive_eligible /authenticated_completion /=.
qed.

lemma degraded_archive_payload_is_raw_publishable :
  let s = run OrdinaryReader ArchivePayload
    (checked_prefix ++ [CompleteDegraded; EnterCallback; UseArchive; UsePublish;
                       RecordPublication PublishedDurable; ReturnCallback; UsePublish]) in
  s.`outcome = Degraded /\ !authenticated_completion s /\
  s.`archive_actions = 0 /\ s.`publish_actions = 1 /\ s.`published = PublishedDurable.
proof.
rewrite /run /checked_prefix /initial /= /ordinary_complete /=.
by do 4! rewrite /callback_live /archive_eligible /authenticated_completion /force_result /=.
qed.

lemma verified_force_keeps_degraded_recovery_authority :
  let s = run ForceReader RawPayload
    [RecoverVerified; RecordPublication PublishedDurable; CompleteHealthy;
     EnterCallback; UseArchive] in
  s.`outcome = ForceVerified /\ s.`published = PublishedDurable /\
  !authenticated_completion s /\ s.`archive_actions = 0 /\ !source_deletion_allowed s.
proof.
rewrite /run /initial /= /recover /= /force_result /= /ordinary_complete /=.
by rewrite /archive_eligible /authenticated_completion /callback_live /source_deletion_allowed /=.
qed.
