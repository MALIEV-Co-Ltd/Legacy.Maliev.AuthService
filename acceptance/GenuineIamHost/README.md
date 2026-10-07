# Isolated genuine IAM host

Build this executable separately from `GenuineIamHttp.Tests`, with the same reviewed `.genuine-iam-source` checkout and `GITHUB_ACTIONS=false` source-reference mode as the acceptance workflow. Do not reference this project from the test project; invoke its built DLL in an owned child process instead. This keeps IAM/OriginalDefaults MassTransit 8 apart from Auth/LegacyDefaults MassTransit 9.

Supply synthetic values only through the child's environment:

- `GENUINE_IAM_CONNECTION`: disposable PostgreSQL connection string.
- `GENUINE_IAM_PRIVATE_PEM`: the synthetic Auth signing private PEM.
- `GENUINE_IAM_PRINCIPAL_ID`: the disposable test user's GUID.
- `GENUINE_IAM_PERMISSION_ID`: the test permission, normally `join.resource.read`.
- `GENUINE_IAM_LIVE_KEY`: the disposable QuotationService live-check credential.

Wait for `GENUINE_IAM_READY=` followed by JSON with `baseAddress`. Send actual HTTP requests to that loopback address. No fake handlers, additional routes, authentication replacement, or production-source edits are used. The host runs in Production and executes the existing startup migrations. Only the fixture v4's four excluded background services are removed. The parent must bound startup waiting because synchronous application initialization can block.

The parent can verify persisted authority with parameterized SQL against `principals` (`principal_id`, `is_active`) and `principal_permission_bindings` (`principal_id`, `permission_id`, `resource_path`). Exactly one test binding must remain for the test principal, permission, and `join/owned` path.

Write `stop` and a newline to stdin. Require process exit code zero and `GENUINE_IAM_STOPPED={"disposed":true,"failedSteps":[]}`. EOF, any other command, or the ten-minute lease expiring fails acceptance. Host disposal has a twenty-second deadline; RSA keys and the owned connection pool are separately released even after a host failure. The parent retains its exact-process termination fallback and exact owned-container cleanup/absence checks. A failure emits only fixed phase names, never exception/configuration payloads.

This host's readiness receipt is not an acceptance pass. The parent must prove the actual allowed/denied, authentication rejection, refresh rejection, persistence, disposal, and container-absence assertions in the hosted lane.
