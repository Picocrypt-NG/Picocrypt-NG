require import AllCore List ReadResultAuthority.

(* Defect: a degraded ordinary completion is accepted as an archive seal. *)
op weakened_archive_eligible (s : state) : bool =
  s.`producer = OrdinaryReader /\ ordinary_complete s /\ s.`kind = ArchivePayload.

op weakened_archive_action (s : state) : state =
  if callback_live s /\ weakened_archive_eligible s
  then {| s with consumed = true; archive_actions = s.`archive_actions + 1 |} else s.

lemma degraded_archive_still_refused :
  let s = run OrdinaryReader ArchivePayload
    (checked_prefix ++ [CompleteDegraded; EnterCallback]) in
  (weakened_archive_action s).`archive_actions = 0.
proof.
rewrite /run /checked_prefix /initial /= /ordinary_complete /=.
rewrite /weakened_archive_action /callback_live /weakened_archive_eligible
        /ordinary_complete /=.
  by done.
qed.
