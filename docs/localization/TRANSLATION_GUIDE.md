# Picocrypt-NG Translation Guide

<!-- markdownlint-disable MD013 MD060 -->
<!-- Wide multilingual tables are intentional in this glossary-style document. -->

This guide defines the translation foundation for Picocrypt-NG. It is not a
string catalog and does not enable localization by itself. It defines the voice,
terminology, review rules, and tooling constraints that every future translation
or Weblate pull request must follow.

Picocrypt-NG is a security-sensitive encryption app. Translation quality is a
security UX concern: translated strings must not promise stronger protection
than the implementation provides, hide risk, or blur authentication,
integrity, password, keyfile, corruption, and deletion concepts.

## Scope

| Surface | Current state | Translation path |
|---|---|---|
| Desktop Fyne UI | Complete bundled application catalogs exist for English, Russian, German, French, Spanish, Simplified Chinese, Hindi, and Korean under `src/internal/ui/translation`. Fyne-owned dialogs and raw backend status text may remain English. | Use the live Weblate Desktop app component and keep the project `tr`/`trn` wrappers. Weblate uses the native go-i18n v2 JSON format; repository tests remain authoritative for keys, placeholders, plural shapes, and runtime registration. |
| Android app | Release resources package the same eight languages: base English plus Russian, German, French, Spanish, Simplified Chinese, Hindi, and Korean. Raw Go/runtime details are not translator source copy. | Use the live Weblate Android app component, Android string resources, and explicit semantic display-boundary mappings. Repository tests keep resource files, release filters, generated LocaleConfig, and semantic checks in lockstep. |
| CLI | Cobra help, prompts, warnings, and errors are hard-coded Go strings. | Do not localize CLI output, command names, flags, or examples. Keep CLI English-only. |
| Web/WASM | The Go WASM bridge exports functions and numeric error codes; it does not own the hosted web UI copy. | Localize the web frontend separately if/when that source is brought into scope. |

Non-goals for the first localization phase:

- Do not modify `crypto`, `header`, `keyfile`, or `volume` semantics.
- Do not translate flags, environment variables, file extensions, protocol names,
  code identifiers, or volume-format fields.
- Do not localize the CLI. CLI help, prompts, errors, stdout/stderr, command
  names, flags, and examples are an English scripting contract.
- Do not translate comments stored inside user volumes. Those are user data.
- Do not let Weblate edit base English catalogs, manage source string IDs, or
  push directly to `main`.

## String Source Of Truth

Do not maintain a full manual string registry in this guide. Full registries
drift from code and become a second source of truth.

The source of truth is platform-native:

| Surface | Source of truth | Rule |
|---|---|---|
| Android app | `android/app/src/main/res/values/strings.xml` | The base English file owns Android UI strings that are resource-backed. Hard-coded Kotlin user messages must be externalized or explicitly mapped before a locale can be released for Android. |
| Desktop Fyne UI | `src/internal/ui/translation/en.json` | Keep the embedded catalog wired through `loadTranslations` and the project `tr`/`trn` wrappers. Do not add locale files without complete-catalog, plural, placeholder, and runtime-registration tests. |
| CLI | none | CLI is not localized. |
| Web/WASM | external web frontend source, if brought into scope | Do not add web UI strings to the Go WASM bridge. |

This guide owns terminology, review rules, and security-critical context. It
does not own every button label or status string.

## Authoritative Sources

Use these sources before adding or changing localization mechanics:

- go-i18n runtime localization: <https://github.com/nicksnyder/go-i18n>
- Fyne app preferences and widgets: <https://docs.fyne.io/>
- Fyne custom theme API: <https://docs.fyne.io/extend/custom-theme/>
- Android localization: <https://developer.android.com/guide/topics/resources/localization>
- Android string resources and plurals: <https://developer.android.com/guide/topics/resources/string-resource>
- Android language and layout support: <https://developer.android.com/training/basics/supporting-devices/languages>
- Android pseudolocales: <https://developer.android.com/guide/topics/resources/pseudolocales>
- Weblate Android resources: <https://docs.weblate.org/en/latest/formats/android.html>
- Weblate go-i18n JSON: <https://docs.weblate.org/en/latest/formats/go-i18n.html>
- Weblate quality checks: <https://docs.weblate.org/en/latest/user/checks.html>
- Weblate hosted pricing and Libre plan: <https://weblate.org/en/hosting/>
- Unicode CLDR plural rules: <https://cldr.unicode.org/index/cldr-spec/plural-rules>
- Unicode LDML / locale identifiers: <https://www.unicode.org/reports/tr35/>
- Unicode grapheme clusters: <https://unicode.org/reports/tr29/>
- HarfBuzz shaping scope: <https://harfbuzz.github.io/what-harfbuzz-doesnt-do.html>
- Noto font-selection guidance: <https://notofonts.github.io/noto-docs/website/use/>
- Microsoft Localization Style Guides: <https://learn.microsoft.com/en-us/globalization/reference/microsoft-style-guides>
- Microsoft Korean Localization Style Guide: <https://aka.ms/korean-styleguide>
- Microsoft Terminology: <https://learn.microsoft.com/en-us/globalization/reference/microsoft-terminology>
- Microsoft Writing Style Guide: <https://learn.microsoft.com/en-us/style-guide/welcome/>
- Google developer translation guidance: <https://developers.google.com/style/translation>
- ANSSI CyberDico: <https://cyber.gouv.fr/cyberdico/>
- INCIBE cybersecurity glossary: <https://www.incibe.es/sites/default/files/contenidos/guias/doc/guia_glosario_ciberseguridad_2021.pdf>

Use Microsoft terminology as practical UI terminology, not as a cryptographic
specification. When it conflicts with Picocrypt-NG semantics, this guide wins.

## Tooling Contract

### Fyne desktop

Picocrypt-NG keeps Fyne/Weblate-shaped flat JSON catalogs under
`src/internal/ui/translation` and loads them through the project-local
`go-i18n` runtime in `src/internal/ui/localization.go`.

- Do not import `fyne.io/fyne/v2/lang` for runtime UI localization.
- Use only the project wrappers `tr` and `trn` from UI code; they centralize
  fallback, plural, template-data, and active-language behavior.
- Desktop Fyne has a compact in-app language selector in the top content
  utility row. The closed control shows a short code such as `en`; the popup
  menu shows native language names. Do not use flags.
- The selected desktop UI language is stored in Fyne preferences under
  `ui.language`.
- Only complete embedded Fyne catalogs appear in the selector. Registered
  desktop codes are `en`, `ru`, `de`, `fr`, `it`, `es`, `zh-Hans`, `hi`, and
  `ko`.
  `zh-Hans` is the catalog filename stem and stored preference, with the open
  menu label `简体中文`; `hi` uses the open-menu label `हिन्दी`; `ko` uses
  `한국어`. Only the closed selector abbreviates `zh-Hans` to `zh`. The open menu
  uses native names and no flags.
  Registration without a catalog does not claim that a locale has shipped:
  `it` remains registered for future work, but `it.json` is absent and Italian
  is not in the bundled selector set.
- Every embedded non-English catalog must exactly match `en.json` message IDs,
  singular/plural shapes, and template placeholders, while using the exact
  plural forms required by the pinned go-i18n version. The current contract is:

  | Locale | Required plural forms |
  |---|---|
  | `en`, `de`, `hi` | `one`, `other` |
  | `fr`, `es` | `one`, `many`, `other` |
  | `ru` | `one`, `few`, `many`, `other` |
  | `zh-Hans`, `ko` | `other` |

  In go-i18n 2.6.1, French and Hindi use `one` for integer zero; French and
  Spanish use `many` for values such as one million. Runtime tests, not this
  table alone, are the executable source of truth. A future Italian catalog
  would require `one`, `many`, and `other`, but is not a shipped row.
- UI state must store semantic display state for labels and UI-owned statuses.
  Do not store translated strings as durable state when the text must relocalize
  after a runtime language switch.
- Use plural APIs for counted strings instead of building `file(s)` strings or
  English-shaped mixed forms such as separate `file_and_folders` keys.
- Keep `en.json` complete. Locale matching should have a generic language file
  when region-specific variants exist; for example, do not add only `fr-FR.json`
  if `fr.json` is missing.
- `en.json` must use Fyne's object shape, not an array of objects:
  `"string.id": "English text"` for singular strings and
  `"string.id": {"one": "...", "other": "..."}` for plurals.
- Prefer stable keyed strings for ambiguous or security-critical copy. Current
  examples include `advanced.force_decrypt.tooltip`,
  `status.kept_output_unverified`, `comments.placeholder`,
  `advanced.delete_volume.label`, and `drop.header_may_be_deniable`.
- Do not put translator comments in Fyne JSON. Keep context in this guide,
  Weblate component metadata, or another maintained project document.

The live Weblate Desktop app component uses **go-i18n v2 JSON**, not generic
JSON or i18next. This format preserves Picocrypt-NG's plural objects and
`{{.Name}}` template markers. On 2026-07-25 Weblate imported all eight desktop
catalogs as 141 strings each, and downloads of every imported catalog were
byte-identical to the repository files. Keep the base English file read-only
and keep source-string management disabled.

### Fyne fonts and packaged rendering

Picocrypt-NG uses Fyne's default theme and system-font fallback. It does not
bundle or download fonts, install operating-system packages, hard-code font
paths, or set `FYNE_FONT`. Nerd Fonts are not a CJK or Devanagari solution.

Fyne's embedded Latin font covers the catalog text required by German, French,
and Spanish. Simplified Chinese, Korean, and Hindi depend on suitable fonts
already available to the operating system. Fyne shapes text with HarfBuzz, but
its preferred system face follows the operating-system locale rather than the
language selected inside Picocrypt-NG. Therefore `zh-Hans`, `ko`, and `hi`
benefit from packaged-build review with matching and non-matching OS locales.

Treat screenshots containing any of the following as rendering defects: tofu,
replacement glyphs, wrong Simplified-Chinese regional forms,
detached Hindi matras, dotted circles, exposed halants, broken conjuncts,
clipped vertical metrics, hidden controls, or window growth beyond the normal
340 px desktop width. Missing system coverage does not authorize adding an
unreviewed font asset.

Emoji and arbitrary mixed-script filenames/comments are platform best-effort.
Font fallback must not change the underlying application string or selected
path and must not cause a crash, but Picocrypt-NG does not promise universal
rendering of every Unicode character or emoji sequence.

### Android

Android must use native string resources.

- `android/app/src/main/res/values/strings.xml` is the base English file for
  resource-backed Android UI strings.
- The complete translated directories are `values-ru`, `values-de`, `values-fr`,
  `values-es`, `values-b+zh+Hans`, `values-hi`, and `values-ko`. Korean uses the
  generic `ko` language tag with contemporary neutral South Korean wording.
  Italian is not packaged.
- AGP generates the per-app locale configuration with
  `androidResources.generateLocaleConfig = true` and filters release resources
  to `en`, `ru`, `de`, `fr`, `es`, `b+zh+Hans`, `hi`, and `ko` through
  `androidResources.localeFilters`. `resources.properties` declares base
  `unqualifiedResLocale=en`; generated output exposes Chinese as `zh-Hans`.
  Debug `en-XA`/`ar-XB` pseudolocales are not release locales.
- Before enabling an Android locale, remove or map remaining hard-coded
  user-facing Kotlin messages for that localized surface. Do not translate raw
  Go error text as source copy.
- Operation status, progress detail, and errors cross the display boundary as
  stable codes plus typed arguments. Compose and the foreground notification
  use the same resource-backed renderer; raw Go/JVM status and error text stays
  diagnostic-only. Unknown status falls back to localized **Working**, and
  malformed/unknown detail is hidden.
- Use positional placeholders such as `%1$s` and `%1$d` so translators can
  reorder arguments.
- Use `<plurals>` for counted strings. Do not write `file(s)`.
- Mark non-translatable technical strings with `translatable="false"` when they
  are resource-backed.
- Run Android pseudolocale checks before accepting broad UI localization.
- Structural completeness and packaging do not certify linguistic quality or
  rendering. Community corrections remain welcome through reviewed Weblate
  pull requests.

The live Weblate Android app component uses:

- File mask: `android/app/src/main/res/values-*/strings.xml`
- Base language file: `android/app/src/main/res/values/strings.xml`
- Format: Android String Resource
- Base editing and source-string management: disabled
- Repository delivery: fork-based GitHub pull requests

### CLI

CLI localization is out of scope. Cobra command names, flags, shell examples,
exit behavior, stdout/stderr, and scripting contracts must stay English-only.
Do not add CLI catalogs or locale-driven CLI output.

### Web/WASM

The Go WASM bridge should not grow UI strings just to support localization. Keep
the bridge API stable and localize the hosted web frontend where the UI lives.

### Hosted Weblate

The live public project is
<https://hosted.weblate.org/projects/picocrypt-ng/>. The Android and desktop
components share one GitHub App repository integration and can only propose
repository changes through pull requests. See
[WEBLATE_SETUP.md](WEBLATE_SETUP.md) for the exact security and operational
contract. Self-hosting remains the fallback if Hosted Libre terms or required
controls change.

Failing Weblate checks for placeholders, XML validity, tags, whitespace,
newlines, plurals, or glossary rules are release blockers unless a maintainer
records a concrete reason for accepting the warning.

## Voice And Style

Use a calm, precise, non-marketing voice.

Good:

- "Verify integrity before decryption."
- "The kept output is unverified and may be corrupted."
- "Comments are plaintext metadata."

Bad:

- "Your data is completely safe."
- "Repair damaged files."
- "Comments are private."
- "Wrong password" when keyfiles, keyfile order, or corruption may be the cause.

General rules:

- Prefer direct action labels for buttons.
- State destructive actions explicitly.
- State known facts as facts. Use "may" only when the result is uncertain.
- Do not blame the user in errors.
- Do not make warnings sound like optional hints when data loss or unverifiable
  output is possible.
- Keep security terms consistent even when a shorter synonym sounds nicer.

Language-specific voice:

| Language | Voice choice |
|---|---|
| Russian | Neutral technical Russian. Prefer concise imperatives or impersonal wording. Avoid bureaucratic phrases like "выполнить удаление". |
| French | Use `vous` in instructions. Use natural French security terms, not literal English calques. |
| German | Use formal-neutral `Sie` in instructions. Avoid English Title Case. Split long compounds with hyphens when readability suffers. |
| Spanish | Use neutral international Spanish. Avoid regional-only terms and avoid relying on either `tú` or `usted` where an impersonal UI phrase works. |
| Italian | Use concise UI actions and impersonal wording. Prefer short labels; use longer technical forms in explanatory text when needed. |
| Simplified Chinese | Use concise Simplified Chinese and review regional glyph forms. Security terms such as deniability need an explanatory tooltip, not only a short label. |
| Hindi | Use concise contemporary technical Hindi. Review conjuncts and matras visually; do not accept code-point presence as shaping proof. |
| Korean | Use concise, professional, contemporary neutral South Korean wording. Avoid unnecessary English when an established Korean technical term exists; keep security limitations explicit. |

## Product Glossary

This table records terminology already present in current or planned catalogs;
it is a review aid, not automatic approval of a translation. Human-reviewed
target entries in the live Weblate glossary and the exact pull-request diff are
authoritative for new changes. If this table disagrees with an approved
Weblate entry, update the table instead of blending the two wordings.

| English concept | Russian | French | German | Spanish | Italian |
|---|---|---|---|---|---|
| Encrypt | Зашифровать | Chiffrer | Verschlüsseln | Cifrar | Cifra |
| Encryption | Шифрование | Chiffrement | Verschlüsselung | Cifrado | Crittografia |
| Decrypt | Расшифровать | Déchiffrer | Entschlüsseln | Descifrar | Decifra |
| Decryption | Расшифровка | Déchiffrement | Entschlüsselung | Descifrado | Decrittografia |
| Password | Пароль | Mot de passe | Passwort | Contraseña | Password |
| Confirm password | Повторите пароль | Confirmer le mot de passe | Passwort bestätigen | Confirmar contraseña | Conferma password |
| Keyfile | Fyne: Ключ-файл; Android: Ключевой файл | Fichier-clé | Schlüsseldatei | Archivo de clave | File chiave |
| Keyfile order matters | Fyne: Порядок ключ-файлов важен; Android: Порядок ключевых файлов важен | L'ordre des fichiers-clés est important | Die Reihenfolge der Schlüsseldateien ist wichtig | El orden de los archivos de clave importa | L'ordine dei file chiave è importante |
| Plaintext metadata | Открытые метаданные | Métadonnées en clair | Klartext-Metadaten | Metadatos en texto claro | Metadati in chiaro |
| Comments are plaintext metadata | Комментарии хранятся как открытые метаданные | Les commentaires sont des métadonnées en clair | Kommentare sind unverschlüsselte Klartext-Metadaten | Los comentarios son metadatos en texto claro | I commenti sono metadati in chiaro |
| Deniability | Правдоподобное отрицание | Déni plausible | Glaubhafte Abstreitbarkeit | Negación plausible | Negabilità plausibile |
| Paranoid mode | Параноидальный режим | Mode paranoïaque | Paranoid-Modus | Modo paranoico | Modalità paranoica |
| Verify integrity first | Сначала проверить целостность | Vérifier d'abord l'intégrité | Integrität zuerst prüfen | Verificar primero la integridad | Verifica prima l'integrità |
| Force decrypt | Принудительная расшифровка | Forcer le déchiffrement | Entschlüsselung erzwingen | Forzar descifrado | Forza decifratura |
| Reed-Solomon | Reed-Solomon | Reed-Solomon | Reed-Solomon | Reed-Solomon | Reed-Solomon |
| Compress | Сжать | Compresser | Komprimieren | Comprimir | Comprimi |
| Split | Разбить на части | Fractionner | Aufteilen | Dividir | Dividi |
| Auto unzip | Автоматически распаковать ZIP | Décompresser automatiquement | ZIP automatisch entpacken | Descomprimir automáticamente | Estrai automaticamente lo ZIP |
| Delete files | Удалить исходные файлы | Supprimer les fichiers | Dateien löschen | Eliminar archivos | Elimina i file originali |
| Delete volume | Удалить зашифрованный том | Supprimer le volume | Volume löschen | Eliminar volumen | Elimina il volume cifrato |
| Output may be corrupted | Вывод может быть поврежден | La sortie peut être corrompue | Die Ausgabe kann beschädigt sein | La salida puede estar dañada | Il file di output potrebbe essere danneggiato |
| Authentication error | Ошибка аутентификации | Erreur d'authentification | Authentifizierungsfehler | Error de autenticación del volumen | Errore di autenticazione |
| Data corruption detected | Обнаружено повреждение данных | Corruption des données détectée | Datenbeschädigung erkannt | Se detectó corrupción de datos | Rilevato danneggiamento dei dati |

Notes:

- Italian UI labels use `Cifra` and `Decifra` for compactness. Longer explanatory
  text may use `crittografare`, `crittografia`, `decrittografare`, or
  `decrittografia` when the sentence needs the technical noun.
- German may use `Datenintegrität` when the object is data integrity rather than
  a generic integrity check.
- Russian may use "проверка подлинности" in broad user-facing text, but
  "аутентификация" is the preferred compact cryptographic UI term here.
- Korean security-sensitive terminology is protected by semantic localization
  tests alongside the structural catalog checks.

## Forbidden Or Dangerous Translations

Do not use these unless a maintainer explicitly approves the exception.

| English concept | Avoid | Why |
|---|---|---|
| Encrypt | encode, codificar, kodieren, закодировать | Encoding is not encryption. |
| Decrypt | open, unlock, apri, sblocca, décrypter, decodificar | Decryption is not ordinary opening; French `décrypter` can imply breaking without the key. |
| Password | key, code, clave, clé, chiave | Passwords and keyfiles are different credentials. |
| Keyfile | key, llave, Schlüssel, ключ | A keyfile is a user-provided file, not only a cryptographic key. |
| Comments | secret notes, private comments | Picocrypt-NG comments are plaintext header metadata. |
| Plaintext metadata | public data, unprotected data | "Public" and "unprotected" overstate or blur the format nuance. |
| Deniability | anonymity, invisibility, hidden mode | Deniability is not anonymity and not a guarantee of being unnoticed. |
| Paranoid mode | maximum security, ultra secure | The mode adds defense in depth; it does not guarantee absolute security. |
| Force decrypt | repair, recover safely, ignore errors | Forced decrypt keeps unverified output and can produce corrupted data. |
| Authentication error | authorization error, login failed | Volume authentication is not account login or access control. |
| Delete | remove from list, clear | Deletion must say what data is actually deleted. |

## Security-Critical Copy Rules

### Authentication

Do not translate authentication failures as "wrong password" unless code knows
the password alone is wrong. In Picocrypt-NG, authentication can fail because of:

- wrong password;
- missing or wrong keyfiles;
- wrong keyfile order;
- damaged or modified volume data;
- unsupported or corrupted header state.

Preferred pattern:

> Authentication failed. Check the password, keyfiles, and keyfile order.

### Integrity and force decrypt

Force decrypt must sound dangerous. It is not repair.

Preferred pattern:

> Integrity check failed. The kept output is unverified and may be corrupted.

Never say the output was recovered safely.

### Comments

Comments stored in volumes are plaintext header metadata. Do not call them
secret, private, encrypted, or protected. Current v2 volumes authenticate header
metadata, including comments, but that does not make comments confidential.

Preferred short pattern:

> Comments are plaintext metadata. Do not put secrets here.

### Deniability

Deniability means plausible deniability of the volume shape, not anonymity.
Avoid "hidden", "anonymous", "invisible", or "undetectable" unless the exact
implementation behavior has been verified for that sentence.

### Delete actions

Always name the object:

- delete input files;
- delete original files;
- delete encrypted volume;
- delete temporary files.

Do not use a generic "delete" label where the user can confuse source files,
output files, keyfiles, and volumes.

## Security-Critical String Registry

Keep this registry small. It covers strings where translation can change
security meaning. It is not a full application string list.

| Risk class | Meaning | Required translator context |
|---|---|---|
| `P0-auth` | Authentication, password, keyfiles, keyfile order, header tamper, and corruption ambiguity. | Failure is not necessarily a wrong password or account-login failure. |
| `P0-integrity` | Verify-first, MAC/integrity checks, corrupted data, force decrypt, and kept output. | Forced output is unverified and may be corrupted; do not describe it as repaired. |
| `P0-deniability` | Deniable wrapper and unreadable header/metadata before decryption. | Deniability is not anonymity, invisibility, or a hidden mode. |
| `P0-metadata` | Comments and header metadata. | Comments are plaintext metadata and must not be described as private or secret. |
| `P1-destructive` | Delete input files, delete encrypted volume, discard output, and temporary cleanup. | Name the deleted or discarded object explicitly. |
| `P1-credential-handling` | Generate, copy, paste, clear password, non-ASCII password normalization, and keyfile creation. | Keep password, keyfile, and key distinct. Mention clipboard or typing risks when present in source. |
| `P2-crypto-options` | Paranoid mode, Reed-Solomon, compression, split, auto-unzip. | Describe behavior, not absolute security or guaranteed repair. |
| `P2-file-flow` | File/folder selection, output naming, app storage, staging, and free-space warnings. | Preserve object identity: input file, output file, volume, folder, temporary file. |
| `P3-status-accessibility` | Progress, foreground service, content descriptions, generic buttons. | Keep status concise and avoid turning state labels into promises. |

Initial high-risk entries:

| Surface | ID or source | Risk class | Translator note |
|---|---|---|---|
| Android | `force_decrypt_warning` | `P0-integrity` | Force decrypt keeps unverified output; it does not repair data. |
| Android | `authentication_error`, `error_auth_failed` | `P0-auth` | This is volume authentication, not login or account authorization. |
| Android | `comments_plaintext_warning` | `P0-metadata` | Comments are plaintext metadata; do not call them private. |
| Android | `comments_not_readable` | `P0-deniability` | Deniability prevents previewing comments before decryption. |
| Android | `deniability_note` | `P0-deniability` | Header metadata cannot be previewed before decryption; this is not anonymity. |
| Android | `keyfiles_required_warning` | `P0-auth` | A keyfile is a user-provided file credential, not a password or cryptographic key label. |
| Android | `keyfile_order_matters` | `P0-auth` | Preserve that the order of keyfiles is required. |
| Android | `discard_output` | `P1-destructive` | The output is discarded/cleaned up, not merely dismissed. |
| Fyne desktop | `advanced.force_decrypt.tooltip`, `status.kept_output_unverified` | `P0-integrity` | Same invariant as Android `force_decrypt_warning`. |
| Fyne desktop | `drop.header_may_be_deniable` | `P0-deniability` | Preserve "may" when header preview cannot prove deniability. |
| Fyne desktop | `comments.placeholder`, `comments.corrupted` | `P0-metadata` | Comments are not confidential; do not call them private or secret. |
| Fyne desktop | `advanced.delete_volume.label`, `advanced.delete_files.label` | `P1-destructive` | Name the deleted object, not a generic delete action. |

## Placeholders, Plurals, And Escaping

- Preserve placeholders exactly: `%s`, `%d`, `%1$s`, `%1$d`, `{name}`,
  `{count}`, `{{ value }}`, and similar markers are not words.
- Use numbered placeholders when a platform supports them.
- Do not concatenate translated sentence fragments in code.
- Do not use `file(s)`. Use platform plural support.
- Every plural resource must have the platform-required fallback form, normally
  `other`.
- Keep keyboard shortcuts, command names, flags, environment variables, file
  extensions, MIME identifiers, package IDs, generated filename prefixes such
  as `encrypted-` and `keyfile-`, and URLs unchanged.
- Android XML strings must escape XML-sensitive characters and Android-sensitive
  leading characters correctly.
- Fyne JSON strings must remain valid UTF-8 JSON and must preserve any template
  markers consumed by the project-local `go-i18n` runtime.

## Reviewer Checklist

Every localization pull request, including one generated by Weblate, must
answer these checks:

1. Does the translation preserve Picocrypt-NG's security meaning?
2. Are password, keyfile, authentication, integrity, and corruption terms
   distinct?
3. Does any string overpromise confidentiality, recovery, deniability, or
   security?
4. Are comments described as plaintext metadata?
5. Does force decrypt clearly say the output is unverified and may be corrupted?
6. Are destructive actions explicit about what gets deleted?
7. Are all placeholders preserved and ordered correctly?
8. Are counted strings implemented through plural resources?
9. Are Weblate checks clean, or is every accepted warning documented?
10. Has the relevant UI been checked for clipped text, especially German,
    Russian, and Korean strings?
11. Has Android been checked with pseudolocales after large resource changes?
12. Are non-translatable identifiers marked or excluded from translation?
13. Does the change leave CLI output untouched?
14. For a Fyne desktop locale, does the complete catalog pass exact key,
    placeholder, message-shape, and locale-plural validation?
15. Has the real packaged desktop UI been checked at 340 px in light and dark
    mode? For `zh-Hans`, `ko`, and `hi`, was shaping checked with both matching
    and non-matching operating-system locales?
16. Are Android build and pseudolocale checks requested only when Android
    resources are actually part of the localization change?

## Pull Request And Release Gates

Before merging a localization pull request:

- Weblate has written only approved units, and a human repository reviewer has
  reviewed the exact pull-request diff.
- A maintainer has checked security-sensitive meaning against this guide.
- No enabled surface depends on untranslated user-facing source text that
  bypasses its platform catalog.
- All placeholder, plural, syntax, and glossary checks are clean.
- Required repository CI is green.

Before merging a new Fyne desktop locale:

- The catalog is complete against `src/internal/ui/translation/en.json` and
  passes the embedded-catalog contract.
- The locale, native display name, and plural forms are registered in the
  runtime and its tests.
- Runtime language switching and preference restoration preserve the full
  locale code.
- Known rendering defects are documented and must not hide or reverse
  security-sensitive meaning or destructive actions.

Before merging a new native Android locale:

- Android resources compile and the relevant UI passes pseudolocale checks.
- The resource directory, `androidResources.localeFilters`, generated release
  LocaleConfig, and semantic catalog registry are in exact lockstep.
- Hard-coded Kotlin user messages for the localized surface have been
  externalized or explicitly mapped.
- Status, detail, and error mappings use semantic resource-backed values; raw
  diagnostic strings are not shown as translated UI.

Community linguistic and real-device review continues after merge as well as
before it. Do not describe a catalog as native-reviewed unless that review is
actually documented, and describe localization in release notes as UI work,
not a cryptographic change.
