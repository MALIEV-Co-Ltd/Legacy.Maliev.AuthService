# Current lockout during confirmation recovery

Web login obtains an opaque confirmation-recovery grant after validating an unconfirmed customer's password. The resend handler must recheck the customer's current lockout when that grant is used. Original Web confirmation recovery rejected a locked account before verifying its provider grant; the migrated action now also rejects an enabled, unexpired lockout before consuming the action or issuing a confirmation challenge.

An enabled deadline exactly equal to the current clock remains locked, matching
the original Identity IsLockedOutAsync comparison. The equality regression leaves
the grant unconsumed and the mapped identity unchanged, then allows that same
grant after expiry. Dedicated confirmation focus contains six cases, including
four current-row lockout variants.

The generic failure and JSON contracts stay unchanged. Expired or disabled lockouts allow recovery. A denial leaves the existing grant available for retry after lockout expiry, within its original lifetime. No identity fields, persistent access-failure counters, provider settings, or schema are changed. This does not make the current process-local login limiter equivalent to original persistent Identity lockout counters, or prove original provider-token interchangeability. A lockout imposed after the current row read can affect the next request; this read is not atomic with external identity updates.
