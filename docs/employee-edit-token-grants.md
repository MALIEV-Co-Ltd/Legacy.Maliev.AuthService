# Genuine interactive employee edit grants

Original actor authority is IdentityKind.Employee from the persisted employee store. Original6c1a4921b3524dd575cab5b1f4aa5774ad9b8997 AuthController.cs SHA256108964703b0acf073e5d0e0081341d63a54d244d473bcc44b43efb50680d4f6c returns Employee/Customer from the authoritative store; TokenGenerator projects the role URI. Original135e526d0dab85c415b3afdcefd7b70fe2c82e2f EmployeesController.cs SHA2568fc9c1b89c0d2d25e9e602f0815af39b45f2382f3c562d56614675db9c73eb23 retains authenticated employee administration. The bounded source establishes no separate job-role administrator tier. Employee-service role catalogue entries are business data, not an additional authentication role.

Current EmployeeService consumers require these five exact scopes for employee update, address read/create/update, and role lookup:

- legacy-employee.employees.update
- legacy-employee.addresses.read
- legacy-employee.addresses.create
- legacy-employee.addresses.update
- legacy-employee.roles.read

RsaAccessTokenIssuer adds only these five claims inside its existing authoritative Employee branch. Existing Employee list/create/read and Customer grants, finite RSA/session binding, workload authentication, configured service permissions, invoice delegation and quotation capability semantics remain intact. No delete scope, role mutation, address-list scope or blanket administrator role is added. Customer does not acquire these claims. Service/scoped issuers do not acquire them automatically; explicitly configured workload permissions remain governed by their existing separate contract. Undefined interactive kinds continue to refuse issuance.

Three normal Production/isolated PostgreSQL controls obtain signed tokens through actual employee credential login, refresh, and Google exchange. Google uses the existing controlled external credential verifier with real service login/nonce, normal exchange, persisted actor lookup and actual access-token issuer; it does not call a live provider. They verify both role spellings, authoritative employee kind, exactly one of each independent literal grant, persisted session/token binding, and success against a normal ServiceDefaults JWT consumer requiring Employee plus each literal scope. A genuine Customer token has no new grants and is denied by every route. Existing normal service and two scoped-issuer controls verify no automatic new grants and deny every route; undefined-kind and unconfirmed/unknown-account controls remain in the dedicated focus. No token with injected employee permissions substitutes for the actual issuer. This small consumer proves signed role/claim interoperability; it does not replace the independent joined EmployeeService/Intranet IAM/resource-path acceptance lane.

Required hosted evidence is forecast until executed: Release zero warnings/errors; full/raw789 zero failed/skipped (reader/Web786 plus three new cases); actor64; dedicated employee-edit-grants8; all prior focuses/readers, six generated sources and six offline EF commands, static/privacy gates. No local native workload, schema/migration apply, live provider, consumer pin, deployment or persistent data change belongs to this slice.
