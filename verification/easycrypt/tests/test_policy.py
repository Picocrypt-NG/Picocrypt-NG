import unittest

from verification.easycrypt.policy import ProofPolicyError, active_text, check_source


class ProofAdmissionPolicy(unittest.TestCase):
    def test_actual_admission_is_rejected(self):
        with self.assertRaisesRegex(ProofPolicyError, 'directive admit at line 2'):
            check_source('lemma unsafe : false.\nproof. admit. qed.')

    def test_nested_comment_mentions_do_not_block_checked_proofs(self):
        text = '(* admitted (* admit *) abort *)\nlemma safe : true.\nproof. trivial. qed.'
        check_source(text)
        self.assertEqual(active_text(text).count('\n'), text.count('\n'))

    def test_quoted_words_and_identifier_suffix_are_not_directives(self):
        check_source('op s = "an \\"admitted\\" proof". op admitted_label = true.')

    def test_undeclared_axiom_cannot_silently_replace_a_proof(self):
        with self.assertRaisesRegex(ProofPolicyError, 'axiom declarations'):
            check_source('axiom the_target : false.')

    def test_tagged_axiom_cannot_bypass_the_manifest(self):
        with self.assertRaisesRegex(ProofPolicyError, 'Unsupported axiom'):
            check_source('axiom [nosmt] unchecked : false.')

    def test_reviewed_primitive_assumption_is_visible(self):
        check_source('axiom keygen_lossless : is_lossless dkey.', ['keygen_lossless'])

    def test_checking_mode_cannot_be_changed_inside_an_owned_proof(self):
        with self.assertRaisesRegex(ProofPolicyError, 'directive pragma'):
            check_source('pragma -check.')

    def test_unterminated_comment_is_not_treated_as_checked_code(self):
        with self.assertRaisesRegex(ProofPolicyError, 'Unterminated'):
            check_source('(* admitted')


if __name__ == '__main__':
    unittest.main()
