require import AllCore BigEndianFields.

lemma narrowed_index_keeps_distinct_values : be32 4294967296 <> be32 0.
proof.
  by rewrite be32_truncation_alias.
qed.
