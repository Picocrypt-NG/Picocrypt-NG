require import AllCore List RecordFraming BigEndianFields.

lemma descriptor_length_low_byte_is_first :
  from_be [nth (byte_of_int 0) (be32 16777216) 0] = octet64 16777216 7.
proof.
  have he := be32_low_octet64 16777216 0 _ _; first 2 by done.
  rewrite he /octet64 /normalize64 /go_remainder64 /be64_modulus
    /be64_divisor /=.
  by done.
qed.
