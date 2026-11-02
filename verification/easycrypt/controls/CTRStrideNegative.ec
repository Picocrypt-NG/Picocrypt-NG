require import AllCore List RecordFraming BigEndianFields RecordDomains.

lemma short_stride_preserves_record_counter_separation :
  ctr_shift15 (nseq 8 (byte_of_int 0)) 0 32768 <>
  ctr_shift15 (nseq 8 (byte_of_int 0)) 1 0.
proof.
  by rewrite /ctr_shift15 from_be_zero /word64_modulus /counter128_modulus.
qed.
