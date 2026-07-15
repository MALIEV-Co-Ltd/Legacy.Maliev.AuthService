# Deployment contract

These manifests are planning artifacts only. Deployment stays disabled until the full legacy migration, staging, capacity and rollback gates pass.

- Existing GKE cluster only. No node pool creation or resize is authorized.
- Namespace: `maliev-legacy` only.
- Existing cluster-wide CloudNativePG operator in `cnpg-system`; no second operator.
- Refresh sessions use a separate logical database and owner role on the single environment cluster `legacy-postgres-<environment>`.
- Customer identity credentials are restricted to the existing identity tables
  but require the minimal row-level operations used by registration,
  confirmation, password recovery, and security-stamp rotation. Employee
  identity administration retains its existing compatibility access. No legacy
  SQL Server schema migration is permitted.
- Runtime values come from the single Google Secret Manager JSON secret `maliev-legacy-secrets`, projected as `legacy-maliev-auth-runtime` by the central GitOps repository.
- The same projection supplies `ServiceClients__Clients__legacy-web__SecretSha256` and numbered permission entries for only `legacy-auth.customer-self-service`, `legacy-customer.customers.create`, `legacy-customer.customers.delete`, `legacy-customer.customers.read`, `legacy-customer.customers.update`, `legacy-customer.addresses.create`, `legacy-customer.addresses.update`, `legacy-customer.companies.create`, `legacy-customer.companies.update`, `legacy-customer.companies.delete`, `legacy.customer-orders.read`, `legacy.customer-orders.cancel`, `legacy-contact.messages.create`, `legacy.quotation-requests.create`, `legacy.quotation-files.write`, `legacy-file.uploads.create`, `legacy-file.uploads.delete`, and `legacy.notifications.send`. Web receives the corresponding raw secret separately; neither repository stores it.
- The placeholder image digest must never be deployed. GitOps receives only a Trivy-scanned immutable digest.
- Initial replica and resource requests are deliberately small to preserve existing cluster capacity. Scaling requires measured capacity evidence and cannot create infrastructure cost.

The authoritative CloudNativePG cluster, backup, secret projection and environment overlays belong in `MALIEV-Co-Ltd/maliev-gitops`, not this service repository.
