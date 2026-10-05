# Deployment contract

These manifests are planning artifacts only. Deployment stays disabled until the full legacy migration, staging, capacity and rollback gates pass.

- Existing GKE cluster only. No node pool creation or resize is authorized.
- Namespace: `maliev-legacy` only.
- Existing cluster-wide CloudNativePG operator in `cnpg-system`; no second operator.
- Refresh sessions use a separate logical database and owner role on the single environment cluster `legacy-postgres-<environment>`.
- Customer identity credentials are restricted to the existing identity tables
  but require the minimal row-level operations used by registration,
  confirmation, password recovery, and security-stamp rotation. Employee
  identity administration retains its existing compatibility access. Source-data
  import and parity rehearsal are external runbook steps; this service only consumes
  the resulting PostgreSQL stores.
- Runtime values come from the single Google Secret Manager JSON secret `maliev-legacy-secrets`, projected as `legacy-maliev-auth-runtime` by the central GitOps repository.
- The same projection supplies `ServiceClients__Clients__legacy-web__SecretSha256`; numbered permission entries for only `legacy-auth.customer-self-service`, `legacy-customer.customers.create`, `legacy-customer.customers.delete`, `legacy-customer.customers.read`, `legacy-customer.customers.update`, `legacy-customer.addresses.create`, `legacy-customer.addresses.update`, `legacy-customer.companies.create`, `legacy-customer.companies.update`, `legacy-customer.companies.delete`, `legacy.customer-orders.read`, `legacy.customer-orders.cancel`, `legacy.customer-quotations.read`, `legacy-contact.messages.create`, `legacy.quotation-requests.create`, `legacy.quotation-files.write`, `legacy-file.uploads.create`, `legacy-file.uploads.delete`, and `legacy.notifications.send`. Web receives the corresponding raw secret separately; neither repository stores it.
- The same projection must also supply `ServiceClients__Clients__legacy-intranet__SecretSha256`; the Intranet client receives the narrowly scoped `legacy-auth.google-identity.exchange` permission in addition to the service permissions it already uses. Web and Intranet receive their raw secrets separately; neither repository stores them.
- Employee Google Identity Services remains disabled unless the runtime projection also supplies `GoogleIdentity__Employee__HostedDomain`, `GoogleIdentity__Employee__Audiences__intranet`, and the matching BFF `Authentication__Google__ClientId`. These are configuration values only; no client credential or private key is committed.
- The placeholder image digest must never be deployed. GitOps receives only a Trivy-scanned immutable digest.
- Initial replica and resource requests are deliberately small to preserve existing cluster capacity. Scaling requires measured capacity evidence and cannot create infrastructure cost.

The authoritative CloudNativePG cluster, backup, secret projection and environment overlays belong in `MALIEV-Co-Ltd/maliev-gitops`, not this service repository.

## Offline manifest review

Run `pwsh -File deploy/Invoke-AuthManifestReview.ps1 -Image registry.example/legacy/auth@sha256:<64-hex-digest>`
to review an immutable image against the planning Deployment. The script renders a unique temporary copy,
runs the offline boundary reviewer, propagates its native process status, and removes the rendered copy
on success or failure. It never modifies the tracked template or invokes cloud authentication, image
publication, Kubernetes, or secret/configuration writes. Child output and exception details are omitted.

The reviewer requires ordinal equality of decoded text with the approved tracked Deployment after exactly one
immutable image substitution. This retains namespace, single replica, resource bounds, non-root/read-only
runtime, health paths and private runtime-secret reference, rejecting extra fields, comments and duplicates.
These are scoped template boundary checks, not Kubernetes schema validation or deployment acceptance.
Historical source resource settings are not authority to resize the current deployment. Project/identity
database compatibility and shared deployment activation gates remain independently owned.

`eng/Test-AuthManifestReview.ps1` exercises real child-process failure propagation, throwaway cleanup,
immutable-image rejection, missing-placeholder and namespace failure, and unchanged source bytes with
synthetic local inputs. Docker context excludes private environment files, logs and rendered manifests.
