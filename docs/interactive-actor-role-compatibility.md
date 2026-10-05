# Interactive actor role compatibility

Original source 6c1a4921b3524dd575cab5b1f4aa5774ad9b8997 added the
Employee/Customer role to ordinary finite identity tokens. The retained source
TokenGenerator writes the literal ClaimTypes.Role URI. Current Auth's normal
validator uses that URI, while frozen Defaults 7edcd961024868513fd5f373cab3dcb261197f77
uses RoleClaimType = "role" with inbound mapping disabled.

Ordinary interactive issuance projects the authoritative identity kind into both
claim names with the same exact value. An explicit switch rejects undefined kinds
before token construction. Normal password login and refresh continue to use
persisted identity/session state. Actor roles do not create permission grants or
change the existing SID, issuer, audience, key or finite lifetime.

Service, invoice-delegation and quotation-invoice capability issuers remain
separate and receive neither actor-role claim. A service identity is not an
employee or customer. No Basic credential adapter, identity-ID password bypass,
HS256 issuer or non-expiring LINE token is restored.

The regressions use normal Production Auth, actual migrated PostgreSQL stores,
real login/refresh and a separate HTTP consumer registered through normal
Production Defaults JWT authentication. Both role mappings, opposite-role
refusal, scoped/machine exclusions and undefined-kind refusal are checked.
This shared-consumer proof is not actual Quotation application acceptance.
Current Quotation main 8adee05519979aa80ac80949f7a0f9dff39305bd uses its
authoritative employee-kind/subject policy; this change does not restore an older
Quotation role policy or establish a current Quotation defect.

Source obligation is the bounded ordinary actor-role portion of 6c1a4921,
with retained controller/issuer/test evidence at checkpoint
135e526d0dab85c415b3afdcefd7b70fe2c82e2f. Whole-source and external LINE
consumer interoperability remain separate. The independent candidate is ordered
after Auth PR137 before combined protected-main acceptance.
