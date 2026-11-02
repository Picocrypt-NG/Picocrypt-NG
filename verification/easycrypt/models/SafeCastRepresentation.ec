require import AllCore IntDiv.

op uint64_modulus : int = 18446744073709551616.
op max_uint64 : int = 18446744073709551615.
op min_int64 : int = -9223372036854775808.
op max_int64 : int = 9223372036854775807.

op uint64_domain (value : int) : bool = 0 <= value < uint64_modulus.
op int64_domain (value : int) : bool = min_int64 <= value <= max_int64.
op unsigned_cast (value : int) : int = value %% uint64_modulus.
op go_signed (value : int) : int =
  if value <= max_int64 then value else value - uint64_modulus.

(* The source contract is a premise; typed representation is separate. *)
op source_contract (value result : int) (ok : bool) : bool =
  ok = (value <= max_int64) /\
  (ok => 0 <= result /\ unsigned_cast result = value) /\
  (!ok => result = 0).

op safe_cast_model (value : int) : int * bool =
  if max_int64 < value then (0, false) else (value, true).

op guarded_go_model (value : int) : int * bool =
  if max_int64 < value then (0, false) else (go_signed value, true).

op guard_disabled_model (value : int) : int * bool = (go_signed value, true).

lemma modulus_is_two_to_64 : uint64_modulus = 2 ^ 64.
proof. by rewrite /uint64_modulus; ring. qed.

lemma unsigned_cast_nonnegative_int64 (result : int) :
  int64_domain result => 0 <= result => unsigned_cast result = result.
proof.
  rewrite /int64_domain /unsigned_cast /min_int64 /max_int64
    /uint64_modulus.
  move=> hr hnonnegative.
  apply pmod_small.
  by smt().
qed.

lemma go_signed_safe (value : int) :
  uint64_domain value => value <= max_int64 => go_signed value = value.
proof. by rewrite /go_signed; smt(). qed.

lemma go_signed_result_range (value : int) :
  uint64_domain value => int64_domain (go_signed value).
proof.
  rewrite /uint64_domain /int64_domain /go_signed
    /uint64_modulus /min_int64 /max_int64.
  by smt().
qed.

lemma guarded_go_model_matches_reference (value : int) :
  uint64_domain value => guarded_go_model value = safe_cast_model value.
proof.
  rewrite /guarded_go_model /safe_cast_model /go_signed.
  by smt().
qed.

lemma typed_source_contract_refines_model (value result : int) (ok : bool) :
  uint64_domain value => int64_domain result =>
  source_contract value result ok => (result, ok) = safe_cast_model value.
proof.
  move=> hv hr [hflag [hsafe hrefused]].
  have hidentity : ok => unsigned_cast result = result.
  + move=> hok.
    apply unsigned_cast_nonnegative_int64 => //.
    by smt().
  rewrite /safe_cast_model.
  case (max_int64 < value) => hbranch; by smt().
qed.

lemma model_result_range (value : int) :
  uint64_domain value => int64_domain (safe_cast_model value).`1.
proof.
  rewrite /uint64_domain /safe_cast_model /int64_domain
    /uint64_modulus /min_int64 /max_int64.
  by smt().
qed.

lemma model_source_contract (value : int) :
  uint64_domain value =>
  source_contract value (safe_cast_model value).`1 (safe_cast_model value).`2.
proof.
  move=> hv.
  have hr := model_result_range value hv.
  rewrite /safe_cast_model /source_contract.
  case (max_int64 < value) => hbranch /=.
  + by smt().
  have hn : 0 <= value by move: hv; rewrite /uint64_domain; smt().
  have hi : int64_domain value by move: hr; rewrite /safe_cast_model; smt().
  have hu := unsigned_cast_nonnegative_int64 value hi hn.
  by smt().
qed.

lemma model_total_on_uint64 (value : int) :
  uint64_domain value =>
  exists (result : int) (ok : bool),
    int64_domain result /\ source_contract value result ok /\
    (result, ok) = safe_cast_model value.
proof.
  move=> hv.
  exists (safe_cast_model value).`1.
  exists (safe_cast_model value).`2.
  have hr := model_result_range value hv.
  have hc := model_source_contract value hv.
  by smt().
qed.

lemma typed_source_contract_unique (value first_result second_result : int)
  (first_ok second_ok : bool) :
  uint64_domain value => int64_domain first_result => int64_domain second_result =>
  source_contract value first_result first_ok =>
  source_contract value second_result second_ok =>
  (first_result, first_ok) = (second_result, second_ok).
proof.
  move=> hv hl hr hleft hright.
  have h1 := typed_source_contract_refines_model value first_result first_ok hv hl hleft.
  have h2 := typed_source_contract_refines_model value second_result second_ok hv hr hright.
  by smt().
qed.

lemma boundary_inputs_are_uint64 :
  uint64_domain 0 /\ uint64_domain max_int64 /\
  uint64_domain (max_int64 + 1) /\ uint64_domain max_uint64.
proof.
  by rewrite /uint64_domain /uint64_modulus /max_int64 /max_uint64.
qed.

lemma model_zero : safe_cast_model 0 = (0, true).
proof. by rewrite /safe_cast_model /max_int64. qed.

lemma model_max_int64 : safe_cast_model max_int64 = (max_int64, true).
proof. by rewrite /safe_cast_model; smt(). qed.

lemma model_first_overflow : safe_cast_model (max_int64 + 1) = (0, false).
proof. by rewrite /safe_cast_model; smt(). qed.

lemma model_max_uint64 : safe_cast_model max_uint64 = (0, false).
proof. by rewrite /safe_cast_model /max_int64 /max_uint64. qed.

lemma guard_disabled_counterexample :
  let value = max_int64 + 1 in
  let candidate = guard_disabled_model value in
  uint64_domain value /\ candidate = (min_int64, true) /\
  int64_domain candidate.`1 /\
  !source_contract value candidate.`1 candidate.`2 /\
  candidate <> safe_cast_model value.
proof.
  by rewrite /guard_disabled_model /go_signed /uint64_domain /int64_domain
    /source_contract /safe_cast_model /uint64_modulus /min_int64 /max_int64.
qed.
