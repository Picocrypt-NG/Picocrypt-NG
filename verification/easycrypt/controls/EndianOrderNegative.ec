require import AllCore List BigEndianFields.

lemma reversed_index_keeps_value : be64 1 = rev (be64 1).
proof.
  by rewrite be64_one_not_reversed.
qed.
