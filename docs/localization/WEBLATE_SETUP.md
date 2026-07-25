# Picocrypt-NG Weblate Setup

This document records the operational and security contract for Picocrypt-NG
localization on Hosted Weblate.

Last verified: 2026-07-25.

## Live Project

- Project: <https://hosted.weblate.org/projects/picocrypt-ng/>
- Android app:
  <https://hosted.weblate.org/projects/picocrypt-ng/android-app/>
- Desktop app:
  <https://hosted.weblate.org/projects/picocrypt-ng/desktop-app/>
- Terminology:
  <https://hosted.weblate.org/projects/picocrypt-ng/terminology/>
- License: `GPL-3.0-only`

The Hosted Weblate GitHub App is installed only for
`Picocrypt-NG/Picocrypt-NG`. Do not add a personal access token, deploy key,
legacy Weblate collaborator, or second Weblate-controlled GitHub identity.

## Security Boundary

Hosted Weblate Libre projects are public. Treat every translation as an
untrusted proposal until both Weblate review and GitHub repository controls
accept it.

The required controls are:

- The repository owner is the only component connected directly to GitHub.
  It uses `github-app`, targets `main`, and has empty push URL and push branch.
  In this configuration Hosted Weblate proposes changes from its fork through
  a pull request instead of pushing to `main`.
- The desktop component links to the Android component with
  `weblate://picocrypt-ng/android-app`, so both surfaces share one repository
  and one pull-request integration.
- GitHub protection for `main` combines an active ruleset requiring a pull
  request, at least one human approval, and dismissal of stale approvals after
  a new push with strict required CI checks in classic branch protection.
- The Weblate GitHub App is not a ruleset bypass actor.
- The repository owner retains an emergency ruleset bypass for recovery. It is
  not assigned to the Weblate App and must not be used for localization pull
  requests.
- Project review is enabled and the commit policy writes only approved
  translations.
- The review team enforces two-factor authentication. Weblate activates review
  privileges only after the maintainer member completes its separate 2FA
  enrollment.
- Automatic suggestion acceptance is disabled.
- Editing base English files and managing source strings are disabled in both
  application components.
- Cross-component translation propagation and contribution to project
  translation memory are disabled. Shared terminology belongs in the glossary.
- Components automatically lock on repository errors.

These controls are layered deliberately. Weblate approval protects the normal
translation workflow; the GitHub ruleset and CI remain the security boundary
if the Weblate account or App is compromised.

## Review Workflow

1. A contributor edits an existing target language or requests a new language
   in Weblate.
2. A Weblate reviewer approves the proposed units. Imported repository content
   must not be bulk-approved merely to make statistics green.
3. Weblate creates or updates a pull request from its fork.
4. GitHub CI validates catalog structure, placeholders, plurals, locale
   registration, and the affected application build.
5. A human repository reviewer inspects the exact diff and approves it.
6. A maintainer merges the pull request.

Community linguistic review is continuous. Existing bundled translations are
not presented as certified native-language reviews; corrections follow the
same reviewed pull-request path.

## Components

### Android App

- VCS owner: yes
- VCS: GitHub via Hosted Weblate GitHub App
- Branch: `main`
- Push URL: empty
- Push branch: empty
- File mask: `android/app/src/main/res/values-*/strings.xml`
- Base file: `android/app/src/main/res/values/strings.xml`
- Format: Android String Resource
- Base language: English
- Edit base file: disabled
- Manage strings: disabled
- Adding a translation: create a new language file
- Language-code style: Android

The imported languages are `en`, `ru`, `de`, `fr`, `es`, `zh-Hans`, `hi`, and
`ko`. Weblate maps Simplified Chinese to `values-b+zh+Hans`; Korean uses
`values-ko`.

Android release admission is intentionally separate from file creation. The
repository test suite requires the actual `strings.xml` directories,
`androidResources.localeFilters`, generated release LocaleConfig, and semantic
catalog registry to stay in lockstep. A pull request adding a language cannot
merge until all of those contracts and the relevant plural rules are updated.

### Desktop App

- VCS owner: no; linked to `Android app`
- Repository link: `weblate://picocrypt-ng/android-app`
- File mask: `src/internal/ui/translation/*.json`
- Base file: `src/internal/ui/translation/en.json`
- Format: go-i18n v2 JSON
- Base language: English
- Edit base file: disabled
- Manage strings: disabled
- Adding a translation: create a new language file
- Language-code style: BCP 47 with hyphens

Do not switch this component to generic JSON or i18next. Picocrypt-NG catalogs
use go-i18n v2 plural objects such as:

```json
{
  "keyfiles.count": {
    "one": "{{.Count}} keyfile",
    "other": "{{.Count}} keyfiles"
  }
}
```

On 2026-07-25 Hosted Weblate imported all eight desktop catalogs as 141 strings
each. Downloads of every imported catalog were byte-identical to the
corresponding repository file. Repository tests independently require exact
keys, message shapes, placeholders, locale plural forms, and language
registration.

### CLI

No component. Command names, flags, help, diagnostics, stdout/stderr, and shell
examples remain an English scripting contract.

## New Languages

Weblate may create a target-language file, but the file alone does not make the
language shippable.

An Android language pull request must also:

- add the Android resource qualifier to `androidResources.localeFilters`;
- register its catalog and CLDR plural quantities in the localization tests;
- pass the generated release LocaleConfig and Android localization tests.

A desktop language pull request must also:

- register the locale and its native display name in the desktop language list;
- define and test the go-i18n plural contract for the locale;
- pass the embedded-catalog, placeholder, and runtime localization tests.

This permits contributors to propose new languages while ensuring that an
unregistered or untested catalog cannot silently enter a release.

## Glossary

The project glossary owns shared security terminology and explanations. It
currently contains 19 source terms covering:

- Picocrypt NG and Picocrypt-NG;
- Reed-Solomon;
- encryption and decryption;
- password and keyfile;
- comments as plaintext metadata;
- authentication, integrity, and corruption;
- deniability and Paranoid mode;
- force decrypt and verify first;
- destructive delete actions.

`Picocrypt NG`, `Picocrypt-NG`, and `Reed-Solomon` are both terminology and
untranslatable entries, so Weblate keeps their spelling in every glossary
language. The remaining terminology entries deliberately await human
target-language translations. Glossary guidance does not replace the
repository's semantic regression tests or human review.

## Operational Checks

Before opening components after setup or an incident:

1. Confirm the project and every component are locked while configuration is
   changing.
2. Confirm the GitHub App is still limited to this repository.
3. Confirm the VCS owner still uses `github-app`, with empty push URL and push
   branch, and the desktop component is still linked to it.
4. Confirm base editing, source-string management, propagation, project
   translation memory, and suggestion auto-accept remain disabled.
5. Confirm at least one maintainer has active Review-team privileges after 2FA
   enrollment.
6. Confirm approved-only commits and the GitHub approval/CI rules are active.
7. Confirm a real upstream merge reaches Weblate through the GitHub App hook.
8. Use the first genuine approved translation correction as the outbound
   canary; do not fabricate a translation solely to create a test pull request.

If any invariant fails, keep the project locked and repair the configuration
before accepting contributions.

## Hosted Libre

Eligibility was rechecked on 2026-07-25. Hosted Weblate describes Libre hosting
as gratis for eligible public libre projects. Picocrypt-NG must keep the live
Weblate link visible in its README and recheck the current terms if the hosting
plan or project visibility changes. Self-hosting remains the fallback if
Hosted Libre terms or required controls no longer fit this project.

## Sources

- Hosted Weblate plans: <https://weblate.org/en/hosting/>
- Code-hosting integration:
  <https://docs.weblate.org/en/latest/admin/code-hosting.html>
- Component configuration:
  <https://docs.weblate.org/en/latest/admin/projects.html>
- Access control: <https://docs.weblate.org/en/latest/admin/access.html>
- Version-control links: <https://docs.weblate.org/en/latest/vcs.html>
- Android resources:
  <https://docs.weblate.org/en/latest/formats/android.html>
- go-i18n JSON:
  <https://docs.weblate.org/en/latest/formats/go-i18n.html>
- Glossaries: <https://docs.weblate.org/en/latest/user/glossary.html>
- GitHub rulesets:
  <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>
