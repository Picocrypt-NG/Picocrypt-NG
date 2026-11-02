require import AllCore D1RecordIntegrity.

lemma omitted_d1_index_preserves_record_separation :
  encode_without_index data_final <> encode_without_index second_data_final.
proof.
  by rewrite omitted_index_alias.
qed.
