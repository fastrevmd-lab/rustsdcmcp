# Temporary mecmcp Compatibility Ledger

This repository has 59 temporary vendor-neutral compatibility symbols:
37 functions/methods and 22 types. Each symbol has exactly one dedicated
mecmcp issue in `docs/mecmcp-compatibility.tsv`.

No compatibility declaration may be added without first creating its dedicated
issue and ledger row. No two rows may share an issue URL.

Migration is all-or-nothing: wait for one coherent mecmcp release containing
every row, pin all mecmcp crates to that single ref, replace imports, delete
`compat`, delete this ledger, and rerun every release gate.

mecmcp [#90](https://github.com/fastrevmd-lab/mecmcp/issues/90) remains the
generic cloud-client work tracker and [#91](https://github.com/fastrevmd-lab/mecmcp/issues/91)
remains the neutral target-vocabulary tracker. Neither is a substitute for a
symbol-specific ledger issue.
