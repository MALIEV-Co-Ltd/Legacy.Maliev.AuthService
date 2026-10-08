# Exact public-source false-positive classification

The installed Gitleaks default `generic-api-key` detector reported two values in
`eng/financial-iam/Materialize-FinancialIamSource.ps1`. Neither is a credential.
The literals and the frozen V3 materializer bytes remain unchanged.

| Line | Exact value | Independently observable source meaning |
| --- | --- | --- |
| 14 | `4f46a141a47f7c85fbefbcdf93872f2b80d28a5cbe4e2e1dd16a34e54673e1ce` | SHA256 of the retained `inputs/auth-source.patch`, the frozen Auth V6 complete source patch. Local raw-file SHA256 readback matches this value; the redacted finding match names `auth-source.patch`. |
| 147 | `85a00d4bb54cf95199ee67dfd97d2b168233ff68` | Auth base commit identifier in `MALIEV-Co-Ltd/Legacy.Maliev.AuthService`; local committed Git object exists as a commit, matching the frozen source association. This identifies source, not repository access or a credential. |

The root `.gitleaks.toml` extends all default rules. Its single targeted allowlist
requires BOTH the exact repository-relative materializer path AND one of these
two exact secret-capture values, and applies only to `generic-api-key`. It does
not allow a whole file, other hashes, other paths, other rules, or future values.
The inherited `.gitleaksignore` is unchanged. The existing publication scanner
invocation remains unchanged and discovers the root configuration normally.

Actual bounded local directory rescan exited 0 using this configuration. Two
negative scans each exited 1: the same public Auth commit under a different path,
and an unclassified high-entropy value under the allowed path. Raw redacted
reports are retained off-repository. This is not full-history scanner clearance
or native qualification; publication still requires its actual CI scanner.
