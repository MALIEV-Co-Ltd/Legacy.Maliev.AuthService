# Auth private-console source migration

Source: `a59193ae2ac030d0e1d373ce4ec50c1b35437391`, parent
`8175e8f3383d31030de2321c480bf6f5bc0fbb2b`. This proposal covers only the Auth
private-console and named-client terminal-observation consumer slice. It is not
whole-commit or multi-owner closure.

The original Auth Program selected the compact production failure console formatter
and registered one outer terminal dependency handler. Current Auth had retained
startup containment and request observations, but ordinary logging still selected
the general scalar-state console formatter. The startup process regression and
accepted OCI revision publisher remain unchanged.

Auth now selects the existing shared private failure formatter and built-in console
provider after AddServiceDefaults. Debug, Trace and Information stay quiet at the
formatter itself, even when a provider-specific category rule enables Trace.
Formatted messages, arbitrary scalar state, scopes, exception messages and stacks
are not console output. Runtime service/version/Activity provenance cannot be
replaced by similarly named state or scope fields.

This is an explicit **private-console-only** adaptation: the general raw-log OTLP
provider is removed with the other general log providers. OpenTelemetry metrics and
tracing registrations, feature gates and exporters remain registered and unchanged.
This does not declare telemetry output, cloud transport or deployed log access
accepted.

The existing six named clients select the shared generic terminal observer:
IAMService, LegacyAuthServiceTokenExchange, QuotationInvoiceLiveAuthority,
InvoiceFinancialOwnership, EmployeeProfileBinding and CustomerProfileBinding.
It observes terminal 5xx responses and the original transport/timeout categories,
not successful or 4xx responses. Existing caller-owned failure suppression is
retained. It does not add retries, change timeouts, redirect/authentication handlers,
credentials, grants, endpoints, bodies, responses or exception identity.

Normal build and container inputs consume accepted ServiceDefaults
`c9f21151639f1911c780f2084dd2d757b4fb3e73` (tree
`499d777880b096097ff1ea70eae4ec2f36b2688b`). The corresponding exact-main push
run `39626541814`, required job `119313160690`, was observed successful.
This advances the existing consumer pin, not the producer or packages. The separate
Genuine IAM graph and all frozen source carriers/pins remain unchanged.

Regressions use actual Production Program DI, provider selection and the selected
formatter. The additional test provider feeds actual ILogger entries through that
same DI-selected formatter into a bounded event recorder; it does not substitute a
general structured-state capture for formatted-output privacy. Named-client cases
retain the actual registered observer while explicitly isolating authentication,
resilience and primary transport. They are observer-registration tests, not real IAM,
financial authority, provider transport, PostgreSQL readiness or full retry proofs.
Health checks are synthetic and host-owned. No genuine credentials or tokens are
minted or sent.

**Open source facet:** ordinary request exceptions still reach the accepted shared
ExceptionHandlingMiddleware as an event with a null exception argument and a
sanitized structured exception type. Its existing privacy contract is retained.
Consequently ordinary Auth HTTP incidents do not yet carry actual MethodBase
sourceLocation. The new formatter regressions preserve async/closure provenance
when the event genuinely carries an exception; that is not proof of ordinary HTTP
throw-site delivery. A separately reviewed provenance adaptation remains required
before whole a591 Auth fidelity can be claimed; do not add a duplicate incident or
forward raw exceptions to an unsafe sink. The selected generic dependency observer
also withholds exception arguments/type provenance. This preserves its accepted
safe event contract and the original terminal-status predicate, but does not claim
the original dependency exception throw-site metadata is delivered. Selecting the
existing source-observation mode instead would introduce additional 4xx events, so
that is not a silent substitute. Dependency provenance also remains a follow-up.

All new build, test, formatter, actual HTTP, observer and full-suite checks are
**NOT RUN** by this source-only author. Exact-head Release zero warnings/errors,
focused/full tests, formatting, static/security, coverage and protected-main
acceptance remain mandatory. Existing source owners and issue #132 stay open as
applicable. No deployment or source-ledger closure is implied.
