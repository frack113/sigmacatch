# Layout

Reference page: the directory tree and the module dependency graph. Read
[Architecture](architecture.md) first — this page is for looking things up.

## Repository tree

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/repository-layout.html?embed=1" loading="lazy" title="Repository layout, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:2223/1257;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Eighteen workspace crates; the eBPF probe and the Windows KMDF driver are
built outside it.*

## Crate dependency graph

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/module-dependency-graph.html?embed=1"
        title="Crate dependency graph, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1162/1096;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Which crate depends on which; inputs implement the `CollectorKind` contract
the runner drives. Drag to pan, scroll to zoom — the Flow animation starts on
its own.*

`sigmacatch-core` owns `evtx_reader` (with the `evtx` dependency) and the
shared regression vocabulary; `sigma-regression` handles `info.yml` and
`sigmacatch-output-regression` writes the sets. `regressiondata-check` reuses
the core modules with `linux-audit-parser` according to each entry's `LogType`.
