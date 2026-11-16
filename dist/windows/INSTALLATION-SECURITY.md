# Per-machine installation destinations

Picocrypt NG Setup checks the final destination before copying application files
or publishing registry entries and shortcuts. This applies to the directory page,
`/D=...`, and the previous installation's 64-bit HKLM `InstallDir`. An explicit
`/D` takes precedence. Without either setting, Setup uses 64-bit Program Files.
An unsupported destination causes Setup to abort with exit code 5.

The check supports ordinary administrator-protected default and custom locations
on local fixed drives with persistent Windows ACLs. Directory and existing
payload owners must be Administrators, SYSTEM, or TrustedInstaller. Only these
principals may receive mutation permissions. Read and execute grants to other
principals are allowed. Mutation includes data/append writes, deletion,
delete-child, permission/owner changes, and directory redirection rights. Every
ancestor is checked; creating unrelated subdirectories alone is allowed there.
For the installation directory, inheritable grants are checked as well.
Inheritance-only CREATOR OWNER grants are accepted only when the elevated
process's default owner is one of the trusted principals.

This is a conservative supported-ACL policy, not a general effective-access
evaluator. It rejects unknown, object, and callback ACE types and untrusted
mutation allow ACEs even when a deny ACE might mask them. Such refusals mean that
Setup cannot verify protection, rather than proving every rejected ACL writable.
Reparse points and junctions, DOS-device aliases such as SUBST, network/removable
destinations, and existing hardlinked payloads are also refused. Administrators
should select a protected directory when a layout is unsupported.

New directories receive a protected ACL granting Administrators and SYSTEM full
control and Users read/execute access. Existing ACLs are never rewritten or
recursively repaired. A data/list-access probe denies write/delete sharing, so
existing data writers cause refusal before publication. This does not detect or
revoke historical security/attribute-only handles, such as WRITE_DAC. Current
ACL inspection cannot prove that every historical capability was revoked. If an
old destination was compromised, choose a new protected location instead of
assuming that rewriting its ACL made it safe.

A supported existing custom directory can be upgraded in
place; an unsafe old destination must be migrated administratively. Setup never
runs an existing uninstaller. The generated uninstaller also checks destination
protection before deleting files or registry entries. The signed-component
export/import procedure is unchanged.

`tests/authority.ps1` runs the real installer on native Windows with a unique
application/registry namespace, synthetic payloads, and temporary standard-user
accounts. Run it in an elevated PowerShell 7 desktop session with `-Repository`,
`-NsisArchive`, and `-Interactive`. The archive is checked by the repository's
NSIS verifier. The tests cover refusal effects, separate-principal write/delete/
rename attempts, protected installations and upgrades, associations, running
instances, and uninstall. Compile and Go policy checks are separate evidence;
Wine does not establish native ACL behavior.
