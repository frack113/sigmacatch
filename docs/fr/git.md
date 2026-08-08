# Workflow Git

Toutes les opérations git passent par **grit-lib** (pure Rust) via le crate `sigmacatch-repo` — jamais de binaire `git` sur le PATH. Les invariants ci-dessous sont non négociables.

## Invariants

### Full-history, jamais shallow

`fetch_options_for_branches()` (`plumbing/fetch.rs`) ne met **jamais** de `depth`, et utilise des refspecs par branche ciblée (jamais `+refs/heads/*`, sauf le glob namespace `+refs/heads/sigmacatch/*`).

Un `depth=1` laisserait l'ODB sans les ancêtres des tips → push cassé après avance du remote (`object not found: <parent oid>`).

### HTTP fetch protocole v2

`AuthHttpClient` (`transport.rs`) envoie `version=2` → publicité capability-only + `ls-refs` scope aux ref-prefix dérivés des refspecs étroits (en v0/v1, GitHub sert **toutes** les remote refs, énorme sur le gros repo Sigma). Le glob `sigmacatch/*` produit le ref-prefix `refs/heads/sigmacatch/` (coupé au premier `*`). SSH utilise déjà v2.

### Branche de travail `sigmacatch/<date>`

Basée sur la remote ref si présente (sinon HEAD) pour garder le fast-forward. Le pull étroit ne met pas à jour `refs/remotes/origin/sigmacatch/<date>` → fetch du namespace `sigmacatch/*` (glob, un fetch, best-effort : panne réseau = `warn!` et on continue avec le worktree uniquement) avant `create_branch`. Branche absente du fork → no-op.

### Skip-set multi-branches (PR en attente)

`pending_regression_rule_ids()` (`SigmaRepo`) scanne les arbres de **toutes** les branches remote `sigmacatch/*` (jamais checkout — `list_refs` + marche `regression_data/` en RAM, ids extraits des noms `<uuid>.<ext>`). Union avec le worktree → une VM fraîche ne recapture pas les données d'un PR d'un autre jour encore ouvert ; le diff du nouveau PR reste basé sur main (données des PR précédents jamais incluses). Les blobs `<uuid>.evtx` sont validés (parse ≥ 1 record) : un EVTX vide/corrompu exclut la règle du skip set (auto-guérison des commits vides). Offline = best-effort (refs déjà fetchées).

### Remote working-branch guard

`check_remote_working_branch()` (startup) valide la branche same-day (commit lisible, ≥ 1 parent, tree avec `rules/`) sinon bail actionnable. Absente → `Ok` (fresh day).

### Worktree = miroir exact du commit

`checkout_main_branch` (`plumbing/checkout.rs`) supprime tout fichier absent de l'arbre (`.git` jamais touché) → skip-set déterministe au startup (les restes d'un push raté ne polluent pas).

### Clone grit complet = objets loose

`is_repo_complete` accepte un repo dès que HEAD résout vers un commit lisible dans l'ODB (pas de `objects/pack`/`packed-refs` requis) ; repo illisible → supprimé + re-cloné.

### Pack après chaque clone/fetch

`pack_loose_objects()` (`plumbing/pack.rs`) consolide les ~131K fichiers loose (~650 MB) en un pack V2 (zlib, pas de delta, rayon) → `.git/` ~218 MB (3x), `fsck` propre, ODB lisible loose ou pack.

## Configuration git

`git.contrib` est opt-in : `true` (ou `--contrib`) active le push sur le fork ; `false` (défaut) = commits locaux, aucun push. `needs_network()` = `!offline || contrib` — token GitHub requis seulement si une opération réseau (pull ou push) est active.

Voir `config.yaml` et les invariants généraux dans [`architecture-reference.md`](architecture-reference.md) pour la configuration complète.
