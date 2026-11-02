require import AllCore List RecordFraming BigEndianFields.

(* Input framing in pcv3credential/{transcript,keys,outer,d1_inner}.go.
   Passwords and ordered digest bytes are supplied AFTER canonicalization and
   factor admission. Hash collision resistance, HKDF/Argon2 security, secret
   provenance, ownership, Unicode and implementation refinement are separate. *)
type transcript_view = {
  credential_mode : int;
  keyfile_mode : int;
  canonical_password : bytes;
  keyfile_count : int;
  ordered_digests : bytes
}.

op valid_transcript (t : transcript_view) : bool =
  0 <= t.`credential_mode < 256 /\ 0 <= t.`keyfile_mode < 256 /\
  size t.`canonical_password <= 1048576 /\
  0 <= t.`keyfile_count <= 64 /\
  size t.`ordered_digests = 32 * t.`keyfile_count.

(* The reserved byte is zero from the source's fresh allocation. The digest
   blob represents the canonical sequence of fixed 32-byte digests. *)
op transcript_header (t : transcript_view) : bytes =
  [byte_of_int 1; byte_of_int t.`credential_mode;
   byte_of_int t.`keyfile_mode; byte_of_int 0].
op transcript (t : transcript_view) : bytes =
  transcript_header t ++
  (be32 (size t.`canonical_password) ++
   (t.`canonical_password ++ (be 2 t.`keyfile_count ++ t.`ordered_digests))).

lemma be16_injective x y :
  0 <= x < 65536 => 0 <= y < 65536 => be 2 x = be 2 y => x = y.
proof.
  move=> hx hy he.
  have hp : 2^16 = 65536 by ring.
  have h := congr1 from_be _ _ he.
  by move: h; rewrite !from_beK //= hp.
qed.

lemma byte_value_injective x y :
  0 <= x < 256 => 0 <= y < 256 => byte_of_int x = byte_of_int y => x = y.
proof.
  move=> hx hy he.
  have h := congr1 (fun b : byte => from_be [b]) _ _ he.
  by move: h; rewrite /= !from_be_byte.
qed.

lemma transcript_injective (t u : transcript_view) :
  valid_transcript t => valid_transcript u => transcript t = transcript u => t = u.
proof.
  rewrite /valid_transcript.
  move=> [htm [htk [htp [htn htd]]]] [hum [huk [hup [hun hud]]]] he.
  have hhsize : size (transcript_header t) = size (transcript_header u)
    by rewrite /transcript_header /=.
  have [hh h0] : transcript_header t = transcript_header u /\
    be32 (size t.`canonical_password) ++
      (t.`canonical_password ++ (be 2 t.`keyfile_count ++ t.`ordered_digests)) =
    be32 (size u.`canonical_password) ++
      (u.`canonical_password ++ (be 2 u.`keyfile_count ++ u.`ordered_digests)).
  + by move: he; rewrite /transcript (eqseq_cat _ _ _ _ hhsize).
  have hmode : t.`credential_mode = u.`credential_mode.
  + apply byte_value_injective => //.
    by move: hh; rewrite /transcript_header /=; smt().
  have hkeymode : t.`keyfile_mode = u.`keyfile_mode.
  + apply byte_value_injective => //.
    by move: hh; rewrite /transcript_header /=; smt().
  have [hlen h1] : be32 (size t.`canonical_password) = be32 (size u.`canonical_password) /\
    t.`canonical_password ++ (be 2 t.`keyfile_count ++ t.`ordered_digests) =
    u.`canonical_password ++ (be 2 u.`keyfile_count ++ u.`ordered_digests).
  + by move: h0; rewrite (eqseq_cat _ _ _ _) 1:!size_be32.
  have hsize : size t.`canonical_password = size u.`canonical_password.
  + apply be32_injective => //; smt(size_ge0).
  have [hpassword h2] : t.`canonical_password = u.`canonical_password /\
    be 2 t.`keyfile_count ++ t.`ordered_digests =
    be 2 u.`keyfile_count ++ u.`ordered_digests.
  + by move: h1; rewrite (eqseq_cat _ _ _ _ hsize).
  have [hcount hdigests] : be 2 t.`keyfile_count = be 2 u.`keyfile_count /\
    t.`ordered_digests = u.`ordered_digests.
  + by move: h2; rewrite (eqseq_cat _ _ _ _) 1:!size_be //.
  have hc : t.`keyfile_count = u.`keyfile_count by apply be16_injective => //; smt().
  by smt().
qed.

type schedule_domain = [ NormalSchedule | D1Schedule ].

op schedule_prefix (d : schedule_domain) : bytes =
  map byte_of_int
    (if d = NormalSchedule then
      [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;72;75;68;70;0]
     else
      [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;68;49;67;47;72;75;68;70;0]).

op valid_request (suite role : int) (label : bytes) : bool =
  0 <= suite < 65536 /\ 0 <= role < 256 /\ size label < 65536.

(* Version 3, schedule version 1, then suite/profile, replica role and label.
   The closed source registries are a subset of this full-width byte model. *)
op schedule_body (suite role : int) (label : bytes) : bytes =
  be 2 3 ++ (be 2 1 ++ (be 2 suite ++
    ([byte_of_int role] ++ (be 2 (size label) ++ label)))).
op schedule_info d suite role label : bytes =
  schedule_prefix d ++ schedule_body suite role label.

lemma schedule_body_injective suite role label suite' role' label' :
  valid_request suite role label => valid_request suite' role' label' =>
  schedule_body suite role label = schedule_body suite' role' label' =>
  suite = suite' /\ role = role' /\ label = label'.
proof.
  rewrite /valid_request /schedule_body.
  move=> [hs [hr hl]] [hs' [hr' hl']] he.
  have h0 : be 2 suite ++ ([byte_of_int role] ++ (be 2 (size label) ++ label)) =
    be 2 suite' ++ ([byte_of_int role'] ++ (be 2 (size label') ++ label')).
  + move: he; rewrite (eqseq_cat _ _ _ _) // => -[_ he].
    by move: he; rewrite (eqseq_cat _ _ _ _) // => -[_ he].
  have [hsuite h1] : be 2 suite = be 2 suite' /\
    [byte_of_int role] ++ (be 2 (size label) ++ label) =
    [byte_of_int role'] ++ (be 2 (size label') ++ label').
  + by move: h0; rewrite (eqseq_cat _ _ _ _) 1:!size_be //.
  have hsc : suite = suite' by apply be16_injective.
  have [hrole h2] : byte_of_int role = byte_of_int role' /\
    be 2 (size label) ++ label = be 2 (size label') ++ label'
    by smt().
  have hrc : role = role' by apply byte_value_injective.
  have [hlabel_length hlabel] : be 2 (size label) = be 2 (size label') /\ label = label'.
  + by move: h2; rewrite (eqseq_cat _ _ _ _) 1:!size_be //.
  by smt().
qed.

lemma schedule_info_domain_binding d e suite role label suite' role' label' :
  schedule_info d suite role label = schedule_info e suite' role' label' => d = e.
proof.
  case: d; case: e => // he.
  + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 18]) _ _ he.
    by move: h; rewrite /schedule_info /schedule_prefix /= !from_be_byte.
  + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 18]) _ _ he.
    by move: h; rewrite /schedule_info /schedule_prefix /= !from_be_byte.
qed.

lemma schedule_info_injective d e suite role label suite' role' label' :
  valid_request suite role label => valid_request suite' role' label' =>
  schedule_info d suite role label = schedule_info e suite' role' label' =>
  d = e /\ suite = suite' /\ role = role' /\ label = label'.
proof.
  move=> hv hw he.
  have hd := schedule_info_domain_binding d e suite role label suite' role' label' he.
  have hb : schedule_body suite role label = schedule_body suite' role' label'.
  + by move: he; rewrite hd /schedule_info eqseq_cat //; smt().
  have h := schedule_body_injective suite role label suite' role' label' hv hw hb.
  by smt().
qed.

(* Normal Extract receives a root and a separate 32-byte VolumeID salt argument.
   This pair is NOT serialized into info. Equal call arguments bind the root
   bytes and VolumeID, without asserting that distinct inputs yield distinct keys.
   Credential-root/VolumeKey selection and randomness remain caller obligations. *)
op normal_key_inputs (root volume_id : bytes) suite role label :
    (bytes * bytes) * bytes * int =
  ((root, volume_id), schedule_info NormalSchedule suite role label, 32).

lemma normal_key_inputs_bind_context root volume_id root' volume_id'
    suite role label suite' role' label' :
  valid_request suite role label => valid_request suite' role' label' =>
  normal_key_inputs root volume_id suite role label =
    normal_key_inputs root' volume_id' suite' role' label' =>
  root = root' /\ volume_id = volume_id' /\
    suite = suite' /\ role = role' /\ label = label'.
proof.
  rewrite /normal_key_inputs.
  move=> hv hw he.
  have hinfo : schedule_info NormalSchedule suite role label =
    schedule_info NormalSchedule suite' role' label' by smt().
  have h := schedule_info_injective NormalSchedule NormalSchedule
    suite role label suite' role' label' hv hw hinfo.
  by smt().
qed.

op credential_prefix (is_d1 : bool) : bytes = map byte_of_int
  (if is_d1 then
    [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;68;49;67;47;
     99;114;101;100;101;110;116;105;97;108;47;102;117;108;108;0]
   else
    [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;
     99;114;101;100;101;110;116;105;97;108;47;110;111;114;109;97;108;0]).
op credential_hash_input is_d1 t : bytes = credential_prefix is_d1 ++ transcript t.

lemma credential_hash_input_injective is_d1 is_d1' t u :
  valid_transcript t => valid_transcript u =>
  credential_hash_input is_d1 t = credential_hash_input is_d1' u =>
  is_d1 = is_d1' /\ t = u.
proof.
  move=> ht hu he.
  have hd : is_d1 = is_d1'.
  + case: is_d1 he; case: is_d1' => // _ he.
    + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 18]) _ _ he.
      by move: h; rewrite /credential_hash_input /credential_prefix /= !from_be_byte.
    + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 18]) _ _ he.
      by move: h; rewrite /credential_hash_input /credential_prefix /= !from_be_byte.
  have hh : transcript t = transcript u.
  + by move: he; rewrite hd /credential_hash_input eqseq_cat //; smt().
  by smt(transcript_injective).
qed.

op d1_root_prefix (is_inner : bool) : bytes = map byte_of_int
  (if is_inner then
    [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;68;49;67;47;
     105;110;110;101;114;47;114;111;111;116;0]
   else
    [80;105;99;111;99;114;121;112;116;45;78;71;47;80;67;86;51;47;68;49;67;47;
     111;117;116;101;114;47;114;111;111;116;0]).
op d1_root_context is_inner profile : bytes = d1_root_prefix is_inner ++ be 2 profile.

lemma d1_root_context_injective is_inner is_inner' profile profile' :
  0 <= profile < 65536 => 0 <= profile' < 65536 =>
  d1_root_context is_inner profile = d1_root_context is_inner' profile' =>
  is_inner = is_inner' /\ profile = profile'.
proof.
  move=> hp hp' he.
  have hd : is_inner = is_inner'.
  + case: is_inner he; case: is_inner' => // _ he.
    + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 22]) _ _ he.
      by move: h; rewrite /d1_root_context /d1_root_prefix /= !from_be_byte.
    + have h := congr1 (fun b : bytes => from_be [nth (byte_of_int 0) b 22]) _ _ he.
      by move: h; rewrite /d1_root_context /d1_root_prefix /= !from_be_byte.
  have hh : be 2 profile = be 2 profile'.
  + by move: he; rewrite hd /d1_root_context eqseq_cat //; smt().
  by smt(be16_injective).
qed.

(* A single omitted role collapses the front/tail request even when every
   other field is retained. Production includes the role byte. *)
op schedule_without_role d suite label : bytes =
  schedule_prefix d ++
    (be 2 3 ++ (be 2 1 ++ (be 2 suite ++ (be 2 (size label) ++ label)))).
op role_omission d suite (role : int) label : bytes = schedule_without_role d suite label.

lemma omitted_role_alias d suite label :
  role_omission d suite 0 label = role_omission d suite 1 label.
proof. by rewrite /role_omission. qed.
