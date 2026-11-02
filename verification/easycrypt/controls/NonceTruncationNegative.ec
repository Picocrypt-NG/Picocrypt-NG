require import AllCore List RecordFraming RecordDomains.

lemma truncated_nonce_preserves_index_separation :
  nonce_truncated32 (nseq 16 (byte_of_int 0)) 0 <>
  nonce_truncated32 (nseq 16 (byte_of_int 0)) 4294967296.
proof.
  by rewrite truncated32_nonce_alias.
qed.
