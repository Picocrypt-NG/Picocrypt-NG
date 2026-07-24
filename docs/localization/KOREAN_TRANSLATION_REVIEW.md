# Korean Translation Review

<!-- markdownlint-disable MD013 -->

This note records the engineering and language review for the Korean
application UI catalogs in Picocrypt-NG. It is not evidence of native Korean
fluency, a Fyne/Weblate round-trip, or release admission on its own.

Review date: 2026-07-24.

Scope:

- Fyne application catalog: `src/internal/ui/translation/ko.json`
- Android resources: `android/app/src/main/res/values-ko/strings.xml`
- Fyne-owned dialogs and raw backend status text: may remain English
- CLI: out of scope and still English-only

## Locale Contract

- Use the generic language tag `ko` and native selector name `한국어`.
- Wording is contemporary, neutral Korean as used in South Korea. A `ko-KR`
  restriction is unnecessary because this catalog has no region-specific
  variant.
- Android uses `values-ko`; AGP generates the per-app locale entry.
- Korean cardinal plurals use only `other`. Counted nouns use a counter such as
  `개` after the number or placeholder.

## Terminology Decisions

| English | Korean | Notes |
| --- | --- | --- |
| Encrypt / encryption | 암호화 | Do not describe encryption as encoding. |
| Decrypt / decryption | 복호화 | Do not reduce decryption to opening or unlocking. |
| Password | 비밀번호 | Keep separate from keyfile and cryptographic key. |
| Keyfile | 키 파일 | Keep the space and do not shorten to key. |
| Encrypted volume | 암호화된 볼륨 | Use the longer form when deletion or integrity risk is discussed. |
| Plaintext metadata | 평문 메타데이터 | Comments are not confidential or encrypted. |
| Deniability | 부인 가능 모드 | Explanatory copy may use 그럴듯한 부인 가능성; never use 부인 방지, which means non-repudiation. |
| Paranoid mode | 패러노이드 모드 | Do not claim maximum or absolute security. |
| Integrity check | 무결성 검사 | A failed check means output is unverified. |
| Force decrypt | 강제 복호화 | This is not repair or safe recovery. |
| Unverified output | 검증되지 않은 출력 | It may be corrupted or attacker-controlled. |
| Corrupted / damaged | 손상됨 | Do not imply successful recovery. |

## High-Risk Copy Checks

- Authentication failure remains distinct from account authorization and does
  not claim that only the password is wrong. It directs the user to check the
  password, keyfiles, and keyfile order where relevant.
- Force-decrypt wording says that kept output is unverified and may be
  corrupted. It does not promise repair or safe recovery.
- Comments are described as plaintext metadata and must not contain secrets.
- Deniability is not translated as anonymity, invisibility, an undetectable
  mode, or non-repudiation.
- Destructive actions name the object being deleted, such as original files or
  the encrypted volume.
- `Picocrypt-NG`, `Android`, `MAC`, `MiB`, `ETA`, `Reed-Solomon`, `Serpent`,
  `ZIP`, version numbers, file extensions, and placeholders remain intact.

## Review Evidence And Open Gates

Independent model-assisted passes reviewed Korean terminology, the desktop
catalog contract, and Android resource/placeholder constraints. Repository
tests enforce exact keys, placeholders, plural shape, locale registration, and
Android resource packaging. These checks do not constitute a native-language
review.

Two independent terminology passes rejected `식별 가능한` as stronger than
English "readable" and rejected `합리적` as "rational/reasonable" rather than
"plausible". The catalogs use `판독 가능한` and `그럴듯한 부인 가능성`; semantic
regression tests preserve both decisions.

Before release admission, a native Korean reviewer must check the full desktop
and Android catalogs in context. Packaged desktop and real Android-device
checks must cover Hangul font fallback, clipping, line breaks, font scaling,
security warnings, progress text, and foreground notifications. Until those
checks are recorded, the catalog must not be described as native-reviewed.

Authoritative references:

- Android per-app language preferences:
  <https://developer.android.com/guide/topics/resources/app-languages>
- Unicode CLDR Korean cardinal plural rule (`other` only):
  <https://unicode.org/cldr/charts/49/supplemental/language_plural_rules.html>
- Microsoft Korean Localization Style Guide:
  <https://aka.ms/korean-styleguide>
- Korean academic usage of `그럴듯한 부인 가능성` for "plausible deniability":
  <https://swb.skku.edu/sigs/article.do?articleNo=43559&attachNo=39104&mode=download>
