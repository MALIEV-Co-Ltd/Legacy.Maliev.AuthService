# Administrative initial password policy

Original checkpoint `135e526d0dab85c415b3afdcefd7b70fe2c82e2f` configures
Intranet, CustomerService and EmployeeService identity creation with minimum
length six and six distinct characters, with the uppercase, lowercase, digit
and non-alphanumeric requirements disabled. Web deliberately uses minimum
length eight and one distinct character. These are separate creation policies.

New customer/employee administrative creation now requires at least six distinct
UTF-16 characters and the existing six-to-1024 request length bounds. The finite
application policy is checked by ordinary create controllers and their actual
write services. Invalid new passwords return generic 400 ProblemDetails without
echoing credentials. Service-owned customer reconciliation first checks existing
ownership receipts; only new creation is subject to the new rule. Its internal
InvalidPassword outcome maps to the same generic 400 and adds no JSON fields.

No blanket validation attribute is added to the shared customer request DTO:
an already committed receipt can replay its original payload, including an older
low-distinct password, after the existing owner/key/payload/current-identity
checks pass. A changed payload still conflicts. This preserves lost-response
recovery while preventing new weak administrative identities.

Seven actual Production HTTP cases use normal authentication/authorization,
production DI, PasswordHasher and PostgreSQL stores. They exercise all three
creation routes, internal service rejection, unchanged identities/receipts/session
counts after rejection, six lowercase-character success and real actor JWT/session
binding, safe receipt replay, the deliberate Web signup policy, and a fixed
independent PBKDF2 receipt for previously committed low-distinct credentials.
Null, empty, short and 1025-character inputs fail without writes. Separate actual
write cases accept the 1024-character maximum and six distinct UTF-16 code units
including a surrogate pair, matching the original Identity character semantics.
Only the existing external Google credential validator remains controlled; the
fixture opt-in adds two test service permissions without replacing auth services.

The Web HTTP witness exposed a separate normal-DI transaction defect: identity
contexts enable retries, while registration and resolve opened explicit
transactions outside the execution strategy. The resulting generic non-validation
400 hid the failure before any password write. These two endpoints now create a
fresh context for the same configured PostgreSQL store, retain command timeout
120 and the existing advisory transaction lock, and omit automatic retries.
An uncertain commit is not replayed blindly; the caller's existing resolve path
still requires the committed password and current compatible customer link.
The normal injected context retains its retry configuration for other callers.
The same HTTP witness checks that production retries remain configured, then
requires registration 201, same-customer credential resolution 200, wrong-password
and different-positive-link 404 with every identity property unchanged. The
existing direct registration/concurrency and nine resolve regression cases remain
required. See [EF Core transaction/retry semantics](https://learn.microsoft.com/en-us/ef/core/miscellaneous/connection-resiliency).

Intranet's current `CustomerIdentityCreationClient` posts the same request and
durable Idempotency-Key to `/auth/v1/customer-identities/{id}/reconcile-create`.
No consumer body, success receipt, authorization, hashing format, schema, role,
counter or dependency pin changes. Employee reset and customer self-service
password creation/change/reset retain their separate current policies; this
bounded change does not claim whole UserManager or production hash inventory parity.
