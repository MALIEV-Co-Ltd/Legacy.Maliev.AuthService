# Explicit interactive password-attempt accounting

Original checkpoint `135e526d0dab85c415b3afdcefd7b70fe2c82e2f` Web and Intranet
use SignInManager password checks with lockoutOnFailure and the five-attempt,
five-minute options. Web's unconfirmed-customer fallback additionally performs
AccessFailedAsync for wrong passwords and ResetAccessFailedCountAsync for a
verified password before offering email-confirmation recovery. Employee
confirmation is checked before password admission.

Normal interactive login now resolves an explicit credential validator that
locks and re-reads the selected existing PostgreSQL identity row. The original
LegacyIdentityReader remains read-only for direct callers, refresh and Google
identity reads. Normal PasswordHasher still accepts supported historical hashes
without rewriting them. Successful validation returns the same verified row
snapshot while its lock is held.

Only AccessFailedCount, LockoutEnd and ConcurrencyStamp may be updated. Failures
one through four increment the count; the fifth resets it to zero and sets the
deadline five minutes ahead. AccessFailedAsync records these fields even when
LockoutEnabled is false; enforcement alone honors that flag. An enabled deadline
equal to now remains locked, matching the source Identity check. Expired lockout
ends are retained. Correct non-TFA passwords reset a nonzero count; an already
zero count is a no-op. Unknown and unconfirmed employee accounts have no writes.
Verified unconfirmed customers reset before the recovery grant, with no session.

A row lock fences these writes against recovery and password updates using the
same identity row; ConcurrencyStamp alone is not assumed to be an EF concurrency
token. A fresh context uses the same selected connection and command timeout but
does not enable automatic retries for this transaction: an uncertain commit must
not blindly apply a second attempt. Credential reads retain the normal reader.
Password verification and projection reuse a pure helper over the already locked
row with the registered PasswordHasher. Neither that verification nor the dummy
verification performs another database query or acquires a second connection.
Accounting commits before action/session issuance; persistence failures cannot
issue either. This does not make the identity and session databases one transaction.

Sixteen new Production HTTP/PostgreSQL cases exercise both kinds' sequential and
concurrent failures, fifth-attempt deadline and equality/expiry, disabled lockout,
successful resets, unknown/unconfirmed admission, customer recovery, concurrent
failure/success ordering, and real PostgreSQL trigger faults for failure/reset
persistence, plus a competing real row transaction that replaces a password while
the HTTP login is observed waiting on its lock; only the replacement credential
can then issue a stamp-bound session. Two more cases deliberately fill a two-
connection identity pool with blocked row queries before releasing the fence:
all eight requests must finish without a secondary-reader acquisition. A
confirmed-TFA success witness retains the explicitly deferred no-reset contract.
Failure paths release fixture row transactions and drain pending HTTP requests.
Existing historical-password and identity-id negative witnesses now
allow exactly the selected three accounting fields while preserving every other
field in both identity stores, credentials, role/session binding and generic errors.
Direct reader tests keep their original read-only contract.

Confirmed accounts with TwoFactorEnabled retain their count on password success:
the original valid-provider and remembered-client reset conditions are not
recreated here. Whole TFA/SignInManager/UserManager, automatic hash upgrade,
data-protection providers and production identity inventories remain separate
parity obligations. Current non-TFA role projection, service login, token wire
shape, process/IP throttles, migrations, live data and dependency pins are unchanged.
