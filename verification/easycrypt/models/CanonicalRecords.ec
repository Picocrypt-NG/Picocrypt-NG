require import AllCore IntDiv.
require SafeCastRepresentation.

op chunk_size : int = 1048576.
op maximum_record_count : int = 281474976710656.
op reachable_count_bound : int = 17592186044416.

op canonical_count (length : int) : int =
  if length = 0 then 0 else (length - 1) %/ chunk_size + 1.

op count_contract (length count : int) : bool =
  0 <= count <= reachable_count_bound /\
  (length %% chunk_size = 0 => count = length %/ chunk_size) /\
  (length %% chunk_size <> 0 => count = length %/ chunk_size + 1).

op chunk_length (length index : int) : int =
  min chunk_size (length - index * chunk_size).

lemma canonical_count_zero : canonical_count 0 = 0.
proof. by rewrite /canonical_count. qed.

lemma positive_count_interval (length : int) :
  0 < length =>
  0 < canonical_count length /\
  (canonical_count length - 1) * chunk_size < length <=
    canonical_count length * chunk_size.
proof.
  move=> hpositive.
  have hdiv := divz_eq (length - 1) chunk_size.
  have hmod := modz_ge0 (length - 1) chunk_size _.
  + by rewrite /chunk_size.
  have hupper := ltz_pmod (length - 1) chunk_size _.
  + by rewrite /chunk_size.
  have hquot := divz_ge0 (length - 1) chunk_size _.
  + by rewrite /chunk_size.
  rewrite /canonical_count.
  by move: hdiv hmod hupper hquot; rewrite /chunk_size; smt().
qed.

lemma interval_determines_count (length count : int) :
  0 < length =>
  (count - 1) * chunk_size < length <= count * chunk_size =>
  count = canonical_count length.
proof.
  move=> hpositive hinterval.
  have hc := positive_count_interval length hpositive.
  by move: hc hinterval; rewrite /chunk_size; smt().
qed.

lemma canonical_count_bound (length : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= canonical_count length <= reachable_count_bound.
proof.
  rewrite /SafeCastRepresentation.uint64_domain
    /SafeCastRepresentation.uint64_modulus => hinput.
  case (length = 0) => hzero.
  + by rewrite hzero canonical_count_zero /reachable_count_bound.
  have hp : 0 < length by smt().
  have hc := positive_count_interval length hp.
  by move: hc; rewrite /chunk_size /reachable_count_bound; smt().
qed.

lemma canonical_count_contract (length : int) :
  SafeCastRepresentation.uint64_domain length =>
  count_contract length (canonical_count length).
proof.
  move=> hinput.
  have hb := canonical_count_bound length hinput.
  have hdiv := divz_eq length chunk_size.
  have hlo := modz_ge0 length chunk_size _.
  + by rewrite /chunk_size.
  have hhi := ltz_pmod length chunk_size _.
  + by rewrite /chunk_size.
  case (length = 0) => hzero.
  + by rewrite hzero /count_contract canonical_count_zero mod0z div0z.
  have hp : 0 < length by move: hinput; rewrite
    /SafeCastRepresentation.uint64_domain; smt().
  have hi := positive_count_interval length hp.
  by rewrite /count_contract; move: hi hdiv hlo hhi;
    rewrite /chunk_size; smt().
qed.

lemma source_contract_refines_count (length count : int) :
  SafeCastRepresentation.uint64_domain length =>
  count_contract length count => count = canonical_count length.
proof.
  move=> hinput hsource.
  have hmodel := canonical_count_contract length hinput.
  by move: hsource hmodel; rewrite /count_contract; smt().
qed.

lemma canonical_count_zero_iff (length : int) :
  SafeCastRepresentation.uint64_domain length =>
  (canonical_count length = 0 <=> length = 0).
proof.
  move=> hinput.
  case (length = 0) => hzero.
  + by rewrite hzero canonical_count_zero.
  have hp : 0 < length by move: hinput; rewrite
    /SafeCastRepresentation.uint64_domain; smt().
  by have := positive_count_interval length hp; smt().
qed.

lemma reachable_final_index (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index <= canonical_count length =>
  SafeCastRepresentation.uint64_domain index /\
  index < maximum_record_count /\
  canonical_count length + 1 <= maximum_record_count.
proof.
  move=> hinput hindex.
  have hb := canonical_count_bound length hinput.
  by move: hb; rewrite /reachable_count_bound /maximum_record_count
    /SafeCastRepresentation.uint64_domain
    /SafeCastRepresentation.uint64_modulus; smt().
qed.

lemma canonical_chunk_bounds (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index < canonical_count length =>
  0 <= index * chunk_size < length /\
  1 <= chunk_length length index <= chunk_size.
proof.
  move=> hinput hindex.
  have hp : 0 < length.
  + have hz := canonical_count_zero_iff length hinput.
    by move: hinput; rewrite /SafeCastRepresentation.uint64_domain; smt().
  have hc := positive_count_interval length hp.
  by rewrite /chunk_length; move: hc hindex;
    rewrite /chunk_size; smt().
qed.

lemma preceding_chunks_full (length index : int) :
  SafeCastRepresentation.uint64_domain length =>
  0 <= index < canonical_count length - 1 =>
  chunk_length length index = chunk_size.
proof.
  move=> hinput hindex.
  have hp : 0 < length.
  + have hz := canonical_count_zero_iff length hinput.
    by move: hinput; rewrite /SafeCastRepresentation.uint64_domain; smt().
  have hc := positive_count_interval length hp.
  by rewrite /chunk_length; move: hc hindex;
    rewrite /chunk_size; smt().
qed.

lemma last_chunk_conserves_length (length : int) :
  SafeCastRepresentation.uint64_domain length => 0 < length =>
  let last_index = canonical_count length - 1 in
  1 <= chunk_length length last_index <= chunk_size /\
  length = last_index * chunk_size + chunk_length length last_index.
proof.
  move=> hinput hp /=.
  have hc := positive_count_interval length hp.
  by rewrite /chunk_length; move: hc; rewrite /chunk_size; smt().
qed.

lemma exact_chunk_count : canonical_count chunk_size = 1.
proof. by rewrite /canonical_count /chunk_size. qed.

lemma maximum_uint64_count :
  canonical_count SafeCastRepresentation.max_uint64 = reachable_count_bound.
proof.
  by rewrite /canonical_count /chunk_size /reachable_count_bound
    /SafeCastRepresentation.max_uint64.
qed.

op extra_record_count (length : int) : int =
  if length = 0 then 0 else length %/ chunk_size + 1.

lemma extra_record_counterexample :
  canonical_count chunk_size = 1 /\ extra_record_count chunk_size = 2 /\
  !count_contract chunk_size (extra_record_count chunk_size).
proof.
  by rewrite /canonical_count /extra_record_count /count_contract
    /chunk_size /reachable_count_bound.
qed.
