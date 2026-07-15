# Deployment contract

These manifests are planning artifacts only. Deployment stays disabled until the full legacy migration, staging, capacity and rollback gates pass.

- Existing GKE cluster only. No node pool creation or resize is authorized.
- Namespace: `maliev-legacy` only.
- Existing cluster-wide CloudNativePG operator in `cnpg-system`; no second operator.
- Refresh sessions use a separate logical database and owner role on the single environment cluster `legacy-postgres-<environment>`.
- Customer and employee identity connections remain read-only against the current SQL Server source during the compatibility phase.
- Runtime values come from the single Google Secret Manager JSON secret `maliev-legacy-secrets`, projected as `legacy-maliev-auth-runtime` by the central GitOps repository.
- The placeholder image digest must never be deployed. GitOps receives only a Trivy-scanned immutable digest.
- Initial replica and resource requests are deliberately small to preserve existing cluster capacity. Scaling requires measured capacity evidence and cannot create infrastructure cost.

The authoritative CloudNativePG cluster, backup, secret projection and environment overlays belong in `MALIEV-Co-Ltd/maliev-gitops`, not this service repository.
