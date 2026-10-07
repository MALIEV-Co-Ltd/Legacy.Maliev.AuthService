# Transport-only publication boundary

The source-only PR slice consists of the 22 exact reviewed hosted V3 source files,
their raw-byte transport seal/gate/tests, the source-controls workflow and a
path-specific Git attribute and two-value scoped scanner classification. No Auth production/test code or ordinary C# fixture
is staged by this slice. The existing 935/31/11 validation lanes are unchanged.

`source-transport-seal.json` is itself pinned by SHA256 in the verifier. The 22
V3 raw postimages are checked before and after pure tests. Three reviewed new
PowerShell files are deliberately exempted from the repository-wide CRLF
checkout transform; their reviewed LF bytes must not silently change. Accounting
V5 tooling, its raw manifest and two CRLF postimages stay encoded and are decoded
only against their exact original raw SHA256/size seals. This is byte provenance,
not an equivalence claim between old and current producer commits.

The PR source job compiles eight Python sources before testing, checks 22 raw
files/seven decoded inputs, runs 38 reviewed pure mock controls plus five new
transport regressions, and parses three PowerShell sources without execution.
These are source/transport checks only. They launch no SDK, Docker, systemd,
provider, grant, application host or migration. The Windows local import shim is
explicitly non-native; Linux CI does not use it.

The separate manual native workflow is not run merely by publishing or merging
this source slice. Actual Linux manager/private-daemon/proxy/FD/admission/expiry,
source materialization and native build/test qualification remain required
before committing the Auth C# candidate. Candidate 30, ordinary 39, Auth 946 and
Accounting 1671/169/18 counts remain forecasts. Retained baseline CI results are
not evidence that those candidate graphs executed.
