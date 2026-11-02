require import AllCore IntDiv.
require import SafeCastRepresentation.
import StdOrder.IntOrder.

(* Mathematical standard-library API contracts, not implementation proofs. *)
op add_parts (a b c : int) : int * int =
  ((a + b + c) %% uint64_modulus,
   (a + b + c) %/ uint64_modulus).

op mul_parts (a b : int) : int * int =
  ((a * b) %/ uint64_modulus,
   (a * b) %% uint64_modulus).

op checked_add (a b : int) : int * bool =
  let parts = add_parts a b 0 in (parts.`1, parts.`2 = 0).

op checked_mul (a b : int) : int * bool =
  let parts = mul_parts a b in (parts.`2, parts.`1 = 0).

(* Division by zero is outside the Go normal-return contract. *)
op checked_ceil_div (value divisor : int) : int * bool =
  let quotient = value %/ divisor in
  if value %% divisor = 0 then (quotient, true)
  else checked_add quotient 1.

op ceiling (value divisor : int) : int =
  value %/ divisor + (if value %% divisor = 0 then 0 else 1).

lemma low_word_range (value : int) :
  uint64_domain (value %% uint64_modulus).
proof.
  have hlo := modz_ge0 value uint64_modulus _.
  + by rewrite /uint64_modulus.
  have hhi := ltz_pmod value uint64_modulus _.
  + by rewrite /uint64_modulus.
  by rewrite /uint64_domain; smt().
qed.

lemma add_parts_decomposition (a b c : int) :
  a + b + c =
  (add_parts a b c).`2 * uint64_modulus +
  (add_parts a b c).`1.
proof. by rewrite /add_parts /= -divz_eq. qed.

lemma add_parts_carry (a b c : int) :
  uint64_domain a => uint64_domain b => 0 <= c <= 1 =>
  uint64_domain (add_parts a b c).`1 /\
  0 <= (add_parts a b c).`2 <= 1.
proof.
  move=> hl hr hc.
  have hlow := low_word_range (a + b + c).
  have he := add_parts_decomposition a b c.
  rewrite /add_parts /= in he.
  rewrite /add_parts /=.
  by move: hl hr hlow he; rewrite /uint64_domain /uint64_modulus; smt().
qed.

lemma mul_parts_decomposition (a b : int) :
  a * b = (mul_parts a b).`1 * uint64_modulus +
    (mul_parts a b).`2.
proof. by rewrite /mul_parts /= -divz_eq. qed.

lemma mul_parts_range (a b : int) :
  uint64_domain a => uint64_domain b =>
  uint64_domain (mul_parts a b).`1 /\
  uint64_domain (mul_parts a b).`2.
proof.
  move=> hl hr.
  have hleft : 0 <= a <= uint64_modulus - 1
    by move: hl; rewrite /uint64_domain; smt().
  have hright : 0 <= b <= uint64_modulus - 1
    by move: hr; rewrite /uint64_domain; smt().
  have hp : 0 <= a * b by apply mulr_ge0; smt().
  have hb : a * b <= (uint64_modulus - 1) * (uint64_modulus - 1).
  + by apply ler_pmul; smt().
  have hlow := low_word_range (a * b).
  have he := mul_parts_decomposition a b.
  rewrite /mul_parts /= in he.
  rewrite /mul_parts /=.
  by move: hp hb hlow he; rewrite /uint64_domain /uint64_modulus; smt().
qed.

lemma checked_add_flag (a b : int) :
  uint64_domain a => uint64_domain b =>
  (checked_add a b).`2 = (a + b < uint64_modulus).
proof.
  move=> hl hr.
  have hz := divz_eq0 (a + b) uint64_modulus _.
  + by rewrite /uint64_modulus.
  by rewrite /checked_add /add_parts /=;
    move: hl hr hz; rewrite /uint64_domain; smt().
qed.

lemma checked_add_success (a b : int) :
  uint64_domain a => uint64_domain b =>
  (checked_add a b).`2 => (checked_add a b).`1 = a + b.
proof.
  move=> hl hr hok.
  have hf := checked_add_flag a b hl hr.
  rewrite /checked_add /add_parts /=.
  apply pmod_small.
  by move: hl hr; rewrite /uint64_domain; smt().
qed.

lemma checked_add_range (a b : int) :
  uint64_domain (checked_add a b).`1.
proof. by rewrite /checked_add /add_parts /=; apply low_word_range. qed.

lemma checked_mul_flag (a b : int) :
  uint64_domain a => uint64_domain b =>
  (checked_mul a b).`2 = (a * b < uint64_modulus).
proof.
  move=> hl hr.
  have hp : 0 <= a * b.
  + apply mulr_ge0; move: hl hr; rewrite /uint64_domain; smt().
  have hz := divz_eq0 (a * b) uint64_modulus _.
  + by rewrite /uint64_modulus.
  by rewrite /checked_mul /mul_parts /=; smt().
qed.

lemma checked_mul_success (a b : int) :
  uint64_domain a => uint64_domain b =>
  (checked_mul a b).`2 => (checked_mul a b).`1 = a * b.
proof.
  move=> hl hr hok.
  have hf := checked_mul_flag a b hl hr.
  have hp : 0 <= a * b.
  + apply mulr_ge0; move: hl hr; rewrite /uint64_domain; smt().
  rewrite /checked_mul /mul_parts /=.
  apply pmod_small.
  by smt().
qed.

lemma checked_mul_range (a b : int) :
  uint64_domain (checked_mul a b).`1.
proof. by rewrite /checked_mul /mul_parts /=; apply low_word_range. qed.

lemma ceiling_range (value divisor : int) :
  uint64_domain value => uint64_domain divisor => 0 < divisor =>
  0 <= ceiling value divisor <= value.
proof.
  move=> hv hd hp.
  have hv0 : 0 <= value by move: hv; rewrite /uint64_domain; smt().
  have hq := divz_ge0 value divisor hp.
  have hle := leq_div value divisor hv0 _.
  + by smt().
  have he := divz_eq value divisor.
  have hm := modz_ge0 value divisor _.
  + by smt().
  have hmul : value %/ divisor <= (value %/ divisor) * divisor.
  + by apply ler_pemulr; smt().
  by rewrite /ceiling; smt().
qed.

lemma checked_ceil_div_contract (value divisor : int) :
  uint64_domain value => uint64_domain divisor => 0 < divisor =>
  checked_ceil_div value divisor = (ceiling value divisor, true) /\
  uint64_domain (ceiling value divisor).
proof.
  move=> hv hd hp.
  have hr := ceiling_range value divisor hv hd hp.
  have hq := divz_ge0 value divisor hp.
  have hq0 : 0 <= value %/ divisor
    by move: hv; rewrite /uint64_domain; smt().
  have hquot : uint64_domain (value %/ divisor).
  + have hle := leq_div value divisor _ _.
    + by move: hv; rewrite /uint64_domain; smt().
    + by smt().
    by move: hv; rewrite /uint64_domain; smt().
  have hone : uint64_domain 1 by rewrite /uint64_domain /uint64_modulus.
  have hf := checked_add_flag (value %/ divisor) 1 hquot hone.
  have hs := checked_add_success (value %/ divisor) 1 hquot hone.
  rewrite /checked_ceil_div /ceiling.
  case (value %% divisor = 0) => hrem /=.
  + by move: hv hr; rewrite /ceiling hrem /= /uint64_domain; smt().
  by move: hv hr; rewrite /ceiling hrem /= /uint64_domain; smt().
qed.

lemma refused_add_is_not_always_zero :
  checked_add max_uint64 2 = (1, false).
proof.
  by rewrite /checked_add /add_parts /max_uint64 /uint64_modulus.
qed.

lemma refused_mul_is_not_always_zero :
  checked_mul max_uint64 2 = (18446744073709551614, false).
proof.
  by rewrite /checked_mul /mul_parts /max_uint64 /uint64_modulus.
qed.

op unchecked_ceil (value divisor : int) : int =
  ((value + divisor - 1) %% uint64_modulus) %/ divisor.

lemma unchecked_ceiling_counterexample :
  ceiling max_uint64 2 = 9223372036854775808 /\
  unchecked_ceil max_uint64 2 = 0.
proof.
  by rewrite /ceiling /unchecked_ceil /max_uint64 /uint64_modulus.
qed.

(* Source facts require separately checked Go contracts and reviewed mappings.
   Ceiling correspondence lemmas require a positive divisor. *)
op add_source_contract (a b result : int) (ok : bool) : bool =
  uint64_domain result /\ result = (a + b) %% uint64_modulus /\
  ok = (a + b < uint64_modulus).

op mul_source_contract (a b result : int) (ok : bool) : bool =
  uint64_domain result /\ result = (a * b) %% uint64_modulus /\
  ok = (a * b < uint64_modulus).

op ceil_source_contract (value divisor result : int) (ok : bool) : bool =
  uint64_domain result /\
  result = value %/ divisor + (if value %% divisor = 0 then 0 else 1) /\ ok.

lemma checked_add_source_contract (a b : int) :
  uint64_domain a => uint64_domain b =>
  add_source_contract a b (checked_add a b).`1 (checked_add a b).`2.
proof.
  move=> ha hb.
  have hr := checked_add_range a b.
  have hf := checked_add_flag a b ha hb.
  by move: hr hf; rewrite /add_source_contract /checked_add /add_parts /=; smt().
qed.

lemma add_source_contract_refines_model (a b result : int) (ok : bool) :
  uint64_domain a => uint64_domain b => add_source_contract a b result ok =>
  (result, ok) = checked_add a b.
proof.
  move=> ha hb hsource.
  have hmodel := checked_add_source_contract a b ha hb.
  by move: hsource hmodel; rewrite /add_source_contract; smt().
qed.

lemma add_source_contract_unique (a b result1 result2 : int) (ok1 ok2 : bool) :
  uint64_domain a => uint64_domain b =>
  add_source_contract a b result1 ok1 => add_source_contract a b result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof.
  move=> ha hb h1 h2.
  have hm1 := add_source_contract_refines_model a b result1 ok1 ha hb h1.
  have hm2 := add_source_contract_refines_model a b result2 ok2 ha hb h2.
  by smt().
qed.

lemma checked_mul_source_contract (a b : int) :
  uint64_domain a => uint64_domain b =>
  mul_source_contract a b (checked_mul a b).`1 (checked_mul a b).`2.
proof.
  move=> ha hb.
  have hr := checked_mul_range a b.
  have hf := checked_mul_flag a b ha hb.
  by move: hr hf; rewrite /mul_source_contract /checked_mul /mul_parts /=; smt().
qed.

lemma mul_source_contract_refines_model (a b result : int) (ok : bool) :
  uint64_domain a => uint64_domain b => mul_source_contract a b result ok =>
  (result, ok) = checked_mul a b.
proof.
  move=> ha hb hsource.
  have hmodel := checked_mul_source_contract a b ha hb.
  by move: hsource hmodel; rewrite /mul_source_contract; smt().
qed.

lemma mul_source_contract_unique (a b result1 result2 : int) (ok1 ok2 : bool) :
  uint64_domain a => uint64_domain b =>
  mul_source_contract a b result1 ok1 => mul_source_contract a b result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof.
  move=> ha hb h1 h2.
  have hm1 := mul_source_contract_refines_model a b result1 ok1 ha hb h1.
  have hm2 := mul_source_contract_refines_model a b result2 ok2 ha hb h2.
  by smt().
qed.

lemma checked_ceil_div_source_contract (value divisor : int) :
  uint64_domain value => uint64_domain divisor => 0 < divisor =>
  ceil_source_contract value divisor (checked_ceil_div value divisor).`1
    (checked_ceil_div value divisor).`2.
proof.
  move=> hv hd hp.
  have hmodel := checked_ceil_div_contract value divisor hv hd hp.
  by move: hmodel; rewrite /ceil_source_contract /ceiling; smt().
qed.

lemma ceil_source_contract_refines_model (value divisor result : int) (ok : bool) :
  uint64_domain value => uint64_domain divisor => 0 < divisor =>
  ceil_source_contract value divisor result ok =>
  (result, ok) = checked_ceil_div value divisor.
proof.
  move=> hv hd hp hsource.
  have hmodel := checked_ceil_div_source_contract value divisor hv hd hp.
  by move: hsource hmodel; rewrite /ceil_source_contract; smt().
qed.

lemma ceil_source_contract_unique (value divisor result1 result2 : int) (ok1 ok2 : bool) :
  uint64_domain value => uint64_domain divisor => 0 < divisor =>
  ceil_source_contract value divisor result1 ok1 =>
  ceil_source_contract value divisor result2 ok2 =>
  (result1, ok1) = (result2, ok2).
proof.
  move=> hv hd hp h1 h2.
  have hm1 := ceil_source_contract_refines_model value divisor result1 ok1 hv hd hp h1.
  have hm2 := ceil_source_contract_refines_model value divisor result2 ok2 hv hd hp h2.
  by smt().
qed.
