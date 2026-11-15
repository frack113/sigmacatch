# Layout

Reference page: the directory tree and the module dependency graph. Read
[Architecture](architecture.md) first — this page is for looking things up.

## Repository tree

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/repository-layout.html?embed=1" loading="lazy" title="Repository layout, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1449/1285;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*One workspace package, two crates built outside it: the eBPF probes and the
Windows kernel driver.*

## Module dependency graph

<!-- markdownlint-disable MD033 -->
<iframe src="../media/interactive/module-dependency-graph.html?embed=1"
        title="Module dependency graph, interactive (Flow + Live)"
        style="display:block;width:100%;aspect-ratio:1010/852;border:0;margin:0 auto"></iframe>
<!-- markdownlint-enable MD033 -->

*Which module calls which; inputs implement the `CollectorKind` contract the
runner drives. Drag to pan, scroll to zoom — the Flow animation starts on its
own.*

`evtx_reader` depends on `types` + the `evtx` crate. `regressiondata-check`
reuses the same modules (`detection`, `rule`, `regression`, `types`,
`evtx_reader`) with `linux-audit-parser` according to each entry's `LogType`.
