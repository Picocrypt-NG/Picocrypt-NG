require import AllCore CanonicalRecords.

lemma extra_count_must_match_exact_chunk :
  extra_record_count chunk_size = canonical_count chunk_size.
proof.
  by rewrite /extra_record_count /canonical_count /chunk_size.
qed.
