# Picocrypt-NG Weblate Setup

This document is the setup gate for Weblate localization in Picocrypt-NG. It is
operational policy, not a marketing page. Do not open Weblate components until
the gates below are satisfied.

## Eligibility

Eligibility verification date: 2026-07-08.

Current result: Picocrypt-NG is likely eligible for hosted Weblate Libre while
it remains a public libre project. Reverify this before actual setup; this is a
dated finding, not a permanent entitlement.

Weblate's hosted pricing page says the hosted Libre plan is gratis for libre
public projects and has the same limits as the 160k hosted plan. It also says
the hosted Libre plan is only for public projects.

If hosted terms change, Picocrypt-NG no longer qualifies, or release-control
requirements exceed hosted Libre controls, self-host Weblate instead.

## Hosted Libre Risk

Hosted Weblate gratis Libre projects are always Public. In Weblate access
control, Public means visible to everybody, and any authenticated user can
contribute.

Mitigation:

- Treat Weblate contributions as proposed translations only.
- Require Weblate pull requests for repository changes.
- Require maintainer review, security review where applicable, and CI before
  merge.
- Never allow Weblate to push directly to protected release branches.
- Use Weblate locking and review features during pull request review so
  translation changes do not move under review.

## Setup Gates

Before opening any component:

1. Reverify hosted Libre eligibility and access-control behavior.
2. Import the Picocrypt-NG glossary and security terms into Weblate.
3. Configure Weblate to create pull requests, not direct protected-branch
   pushes.
4. Confirm required review and CI branch protection on the target branch.
5. Confirm reviewers understand the P0/P1 rules in
   [TRANSLATION_GUIDE.md](TRANSLATION_GUIDE.md).

Glossaries can be imported with CSV or TBX. Use glossary entry types to mark
brand names, acronyms, features, and security terms by meaning and audience:
regular, Terminology, Untranslatable, or Forbidden.

Weblate checks for placeholders, XML validity, tags, whitespace, newlines,
plurals, and glossary issues are technical gates. They do not replace
native-language review or maintainer/security review.

## Review Rules

- Machine translation may be suggestions only for P0/P1 strings.
- P0/P1 strings require native-language review plus maintainer/security review.
- Placeholder and format checks must be clean before merge, or a maintainer
  must record why a warning is accepted.
- Maintainers must reject translations that overpromise confidentiality,
  recovery, deniability, or security.
- Comments must remain described as plaintext metadata.
- Authentication, password, keyfile, corruption, and integrity terms must stay
  distinct.

## Components

### Android App

Enable Android first, after Android localization gates pass.

Configuration:

- Component: Android app
- File mask: `android/app/src/main/res/values-*/strings.xml`
- Base file: `android/app/src/main/res/values/strings.xml`
- Format: Android String Resource
- Base language: `en`
- Translated languages after Android gates: `ru`, `de`, `fr`, `es`, `zh-Hans`, `hi`
- Android directory mapping: `zh-Hans` uses `values-b+zh+Hans`; Italian is not packaged

Android string resources are monolingual in Weblate. The base file is
`res/values/strings.xml`, and the typical translated file mask is
`res/values-*/strings.xml`. Weblate's Android String Resource format supports
plurals and flags/read-only strings. These are application UI resources;
Fastlane currently has a separate English-only `en-US` store-listing/changelog
surface and must not be inferred from the app-resource language list.

### Fyne Desktop

Do not enable yet.

Fyne Weblate setup is blocked until Picocrypt-NG proves exact round-trip for
the Fyne JSON catalog shape in `src/internal/ui/translation/en.json`.

Seven complete desktop catalogs currently exist for `en`, `ru`, `de`, `fr`,
`es`, `zh-Hans`, and `hi`, but no Fyne/Weblate JSON round-trip has been proved.
The curated Russian Fyne catalog is a maintainer-reviewed in-repository
translation exception. It is gated by
`docs/localization/RUSSIAN_TRANSLATION_REVIEW.md` and structural catalog tests,
not by Weblate. This exception does not prove that Weblate can safely edit Fyne
JSON catalogs.

The desktop language selector does not by itself enable a Fyne Weblate
component. Additional non-English Fyne production catalogs that are imported
from Weblate remain blocked until a real Weblate JSON round-trip proves that
Picocrypt-NG's flat keys, plural objects, UTF-8 content, and placeholder syntax
survive export and import unchanged.

Blocked configuration, for later validation only:

- Component: Fyne desktop
- File mask: `src/internal/ui/translation/*.json`
- Base file: `src/internal/ui/translation/en.json`
- Format: JSON or JSON nested structure file, only after round-trip validation

Required proof before opening the component:

- Weblate export/import preserves existing keys and object shape.
- Fyne plural objects survive unchanged, for example:

  ```json
  {
    "keyfiles.count": {
      "one": "Using {{.Count}} keyfile",
      "other": "Using {{.Count}} keyfiles"
    }
  }
  ```

- Placeholder markers such as `{{.Count}}` survive unchanged.
- Fyne tests still pass after Weblate round-trip.

Weblate's JSON docs say simple and nested JSON are supported and monolingual
JSON with an English base is recommended, but generic JSON has no native plural
support. Do not enable Fyne until that limitation is proven safe for the exact
Fyne catalog objects Picocrypt-NG uses.

### CLI

No component.

CLI output, command names, flags, examples, stdout/stderr contracts, and
diagnostics remain English-only.

## GitHub Integration

Hosted Weblate can use the Hosted Weblate GitHub app to grant repository
access, receive notifications, push translation branches, and create pull
requests.

Picocrypt-NG must configure that integration for pull requests only. Protected
branches must require actual review and CI. Do not waive protected-branch
review for a Weblate push user.

## Sources

- Hosted Weblate pricing and Libre plan:
  <https://weblate.org/en/hosting/>
- Weblate access control:
  <https://docs.weblate.org/en/latest/admin/access.html>
- Hosted Weblate GitHub integration:
  <https://docs.weblate.org/en/latest/vcs.html>
- Weblate protected branches and continuous localization:
  <https://docs.weblate.org/en/latest/admin/continuous.html>
- Weblate Android format:
  <https://docs.weblate.org/en/latest/formats/android.html>
- Weblate JSON format:
  <https://docs.weblate.org/en/latest/formats/json.html>
- Weblate glossary:
  <https://docs.weblate.org/en/latest/user/glossary.html>
- Weblate checks:
  <https://docs.weblate.org/en/latest/user/checks.html>
