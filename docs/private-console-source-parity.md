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
`1fec4ef5c8c24fd57806b952182ae6bdb2d6a7fa` (tree
`fb8d6be44949831eaa8bf2fc8bb4be20863d48b7`). The corresponding exact-main push
run `39695344761`, required job `119551237366`, was observed successful.
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

The ordinary request catch explicitly enables the accepted shared
IncludePrivateFailureProvenance option through AddStandardMiddleware. Each of the
same six generic dependency observers explicitly selects includePrivateProvenance.
The existing catch and terminal handler capture validated runtime CLR type,
immediate inner type and throw-site strings into the shared sealed state. They
still pass a null Exception argument to every logging provider; no Exception,
message, Data, MethodBase reference or stack is retained in that state. This does
not select the source-observation mode or add 4xx dependency incidents.

The real Program regressions retain the original provider-specific Trace override
and all six severity rows. Forged provenance-shaped state remains excluded. The
six actual named-client rows assert real transport exception identity and its
formatted type/inner/throw-site, quiet 200/404 and caller cancellation, and no
Exception argument reaching the failure providers. New ordinary HTTP cases check
the existing plain throw and an actual async throw, a single unchanged critical
500 incident, no duplicate handled incident, and bounded formatted provenance.
These tests isolate upstream transports and synthetic readiness exactly as before;
they do not exercise financial providers or grant any authority.

The earlier console-only slice used accepted c9f2115/tree499d777, exact-main
39626541814/job119313160690. This follow-on selects only the already accepted
Shared95 successor; it does not alter the shared producer. Runtime provenance is
implemented in this source candidate, but its consumer acceptance remains pending
exact-head and protected-main checks. The deployment-script facet and other owners
of original a591 remain separate; no whole-source closure is claimed.

All new build, test, formatter, actual HTTP, observer and full-suite checks are
**NOT RUN** by this source-only author. Exact-head Release zero warnings/errors,
focused/full tests, formatting, static/security, coverage and protected-main
acceptance remain mandatory. Existing source owners and issue #132 stay open as
applicable. No deployment or source-ledger closure is implied.
