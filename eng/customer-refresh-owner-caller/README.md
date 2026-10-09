SOURCE DRAFT — NOT QUALIFIED OR AUTHORIZED FOR DISPATCH.

The caller atomically registers a 3600-second manager invocation with ExecStopPost
before starting the unchanged rendered launcher. Manager shutdown runs cleanup
even if the workflow's waiting client exits. TimeoutStopSec gives this shutdown
hook a separate finite 780-second budget. Inner coordinator 2700 seconds and
recovery 600 seconds remain unchanged. A workflow reserves 90 minutes for the
caller and 100 minutes for the job. Runner destruction cannot guarantee hook
execution; missing receipts or remaining resources must stay unknown.

This is a source implementation awaiting independent review, not a qualified
native route. Exact adapter/backend source seals and current main must be checked
before invoking it. ExecStopPost recovery command identity, bounded readback and
real systemd exit semantics require Linux qualification. No SDK or PostgreSQL
fixture is dispatched. The model controls do not prove manager behavior.

The exclusive fsynced caller intent retains exact argv, source hashes, backend
pins and caps before dispatch. Cleanup requires the typed ExecStopPost command,
actual ControlPID/birth/executable/cgroup and InvocationID. Normal completed
external recovery suppresses redundant dispatch only; physical readback always
checks real absence. Collect-on-failure and exact nonloading inventory readback
produce a caller absence receipt. SIGTERM becomes cancellation with finally
cleanup; runner destruction still cannot establish absence. Cleanup persistence
failure never replaces a retained primary exception.

Fresh original 4 GiB/cgroup-v2 admission and exact manual GitHub identity are
required before allocating even the outer caller. A random retained description
nonce fences predictable unit-name reuse. LimitCORE=0 and the original 256 MiB
file-size bound are retained. Typed command parsing uses the unchanged captured
backend reader with only the requested property name adapted at the command edge.

The failure-path timeout arithmetic is 4380 seconds waiting for the manager,
810 seconds stopping it in finally, 10 seconds observing collection, plus
185 seconds for the first inventory query (5) and six finite manager checks
(6 x 30). This totals 5385 seconds under the 5400-second step, leaving 15
seconds of scheduling/receipt reserve. The 6000-second job also covers the
180-second preflight and leaves 420 seconds for checkout/artifact steps.
These are configured timeout budgets, not a claim that arbitrary filesystem
I/O has a hard wall-clock bound. The registered cleanup hook independently
retains its 780-second shutdown budget if the waiting workflow is interrupted.
# V3 canonical systemd identity correction

V2 remains immutable. V3 requires one explicit `.service` suffix in the caller
plan and uses that same canonical name for durable intent, systemd-run,
properties, typed GetUnit command readback, inventory, stop and absence receipts.
The regression accepts actual systemd-shaped Id and ControlGroup values and
rejects missing suffixes, duplicate suffixes and foreign identities. It also
checks the exact cleanup inventory query. No native manager execution occurred.

