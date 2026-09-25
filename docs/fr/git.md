# Workflow Git

Toutes les opérations git passent par **grit-lib** (pure Rust) via le module `repo` du package `sigmacatch` — jamais de binaire `git` sur le PATH. Les invariants ci-dessous sont non négociables.

## Invariants

### Full-history par défaut ; shallow clone avec unshallow différé (configurable)

`fetch_options_for_branches()` (`plumbing/fetch.rs`) utilise des refspecs par branche ciblée (jamais `+refs/heads/*`, sauf le glob namespace `+refs/heads/sigmacatch/*`).

Par défaut (`git.shallow_clone: true`), le clone initial utilise `depth=1` (seul le commit tip) pour un premier run rapide. Avant tout push, le repo est automatiquement unshallowed (historique complet récupéré) en arrière-plan. Ceci évite le problème d'ancestry au push tout en gardant un premier run rapide.

Mettre `git.shallow_clone: false` dans `config.yaml` pour désactiver le shallow clone et récupérer l'historique complet immédiatement.

### HTTP fetch protocole v2

`AuthHttpClient` (`transport.rs`) envoie `version=2` → publicité capability-only + `ls-refs` scope aux ref-prefix dérivés des refspecs étroits (en v0/v1, GitHub sert **toutes** les remote refs, énorme sur le gros repo Sigma). Le glob `sigmacatch/*` produit le ref-prefix `refs/heads/sigmacatch/` (coupé au premier `*`). SSH utilise déjà v2.

### Retry avec backoff exponentiel

Toutes les opérations réseau (clone, fetch, pull) retry sur échecs transitoires avec backoff exponentiel (5s → 10s → 20s → 40s → 60s max). Configurable via `git.max_retries` (défaut 3) et les champs timeout (`clone_timeout_secs`, `fetch_timeout_secs`, `http_timeout_secs`).

### Sparse checkout (mode cône)

Quand `git.sparse_checkout: true` (défaut), un sparse checkout mode cône est configuré après le clone, ne matérialisant que `rules/`, `rules-emerging-threats/`, `regression_data/`. Cela évite d'écrire le repo Sigma complet (~500MB+ docs/tools/tests) sur disque.

### Branche de travail

Le nom de la branche de travail est configurable via `git.working_branch` dans `config.yaml`
ou le flag `--branch` en ligne de commande. En l'absence ou si vide, la branche par défaut
`sigmacatch/<AAAAMMDD>` (date du jour) est utilisée.

Basée sur la remote ref si présente (sinon HEAD) pour garder le fast-forward. Le pull étroit ne met pas à jour `refs/remotes/origin/sigmacatch/<date>` → fetch du namespace `sigmacatch/*` (glob, un fetch, best-effort : panne réseau = `warn!` avec cause catégorisée — clé SSH/ssh binaire vs token manquant vs réseau — et on continue avec le worktree uniquement) avant `create_branch`. Branche absente du fork → no-op.

**Branche de travail hors `sigmacatch/*` (correction #95)** : Si le nom de la branche de travail ne match pas le pattern `sigmacatch/*` (ex: `feature/mon-test`), elle est maintenant explicitement fetchée depuis le fork avant `create_branch`, donc la branche locale est basée sur le tip du fork au lieu du `HEAD`/`master` local. Cela assure que les re-runs same-day ou noms de branche custom restent en sync avec le remote.

**Skip du master-switch (re-run même jour)** : `is_head_on_working_branch()` inspecte la cible de HEAD (`symbolic_ref_target`) avant `switch_to_tracking_branch()`. Si HEAD est déjà sur `refs/heads/sigmacatch/<date>`, le va-et-vient master → branche de travail est sauté (évite l'aller-retour inutile, corrige le cas Windows sans ssh). Un re-run du même jour reste donc sur la branche de travail directement.

### Skip-set multi-branches (PR en attente)

`pending_regression_rule_ids()` (`SigmaRepo`) scanne les arbres de **toutes** les branches remote `sigmacatch/*` (jamais checkout — `list_refs` + marche `regression_data/` en RAM, ids extraits des noms `<uuid>.<ext>`). Union avec le worktree → une VM fraîche ne recapture pas les données d'un PR d'un autre jour encore ouvert ; le diff du nouveau PR reste basé sur main (données des PR précédents jamais incluses). Les blobs `.evtx` sont validés au scan (taille ≤ 64 MiB puis re-parse `parse_evtx_bytes` complet), les autres extensions (`.log`) sont acceptées sans validation structurelle au scan — la validation approfondie se refait à l'écriture. Un blob `.evtx` illisible, vide ou corrompu exclut la règle du skip set (auto-guérison, RAM bornée). Mode offline : scan sauté entièrement (aucune lecture de refs locale) — le skip set ne couvre que le worktree.

### Remote working-branch guard

`check_remote_working_branch()` (startup) valide la branche same-day (commit lisible, ≥ 1 parent, tree avec `rules/`) sinon bail actionnable. Absente → `Ok` (fresh day).

### Worktree = miroir exact du commit

`checkout_main_branch` (`plumbing/checkout.rs`) supprime tout fichier absent de l'arbre (`.git` jamais touché) → skip-set déterministe au startup (les restes d'un push raté ne polluent pas). **Mode offline** : toutes les opérations git sont des no-op (`init`, working-branch, checkout, commit, push) — les fichiers locaux sont laissés intacts, un `.git` n'est même pas requis (zip sigma extrait), les suppressions et modifications faites pour des tests survivent au redémarrage.

### Clone grit complet = objets loose

`is_repo_complete` accepte un repo dès que HEAD résout vers un commit lisible dans l'ODB (pas de `objects/pack`/`packed-refs` requis) ; repo illisible → supprimé + re-cloné (online uniquement — en offline le repo est utilisé tel quel sans vérification).

### Échec de pull non destructif

`pull()` (`plumbing/fetch.rs`) retourne désormais une `Err` claire avec le contexte (`with_context`) si la lecture de `.git/config` ou le fetch SSH/HTTP échoue — le repo est laissé **tel quel** (pas de `remove_dir_all`, pas de re-clone). L'erreur mentionne le chemin du repo, la cause exacte (ex: config manquant, clé SSH invalide) et suggère le mode offline comme alternative. En startup, `is_repo_complete` conserve son comportement existant (repo illisible → supprimé + re-cloné).

### Pack après chaque clone/fetch

`pack_loose_objects()` (`plumbing/pack.rs`) consolide les ~131K fichiers loose (~650 MB) en un pack V2 (zlib, pas de delta, rayon) → `.git/` ~218 MB (3x), `fsck` propre, ODB lisible loose ou pack.

## Configuration git

`git.contrib` est opt-in : `true` (ou `--contrib`) active le push sur le fork ; `false` (défaut) = commits locaux, aucun push. `needs_network()` = `!offline || contrib` — token GitHub requis seulement si une opération réseau (pull ou push) est active. **`offline: true` neutralise `contrib`** (forcé à `false`, `warn!`) : aucun push ne sera jamais tenté en mode offline.

**Transport SSH** : `git.transport: ssh` + `ssh_key_path` (clé ed25519). `ensure_ssh_host_config()` écrit les directives `IdentityFile`/`UserKnownHostsFile` dans `~/.ssh/config` avant les ops de transport (idempotent, **écriture atomique** tmp + rename pour éviter un fichier partiel ; sautée en mode offline) ; sur Windows, `ssh` est résolu via OpenSSH de Windows / Git for Windows et exécuté en direct (`SshCommand::Program`). Quand `ssh_key_path` est renseigné, chaque commit de régression est signé en ed25519 pure Rust (`ssh-key`) — l'en-tête `gpgsig` reproduit `git commit -S` (le format SSH de la signature s'active via la config git `gpg.format = ssh`) → GitHub affiche "Verified". **Échec du pull SSH = abort** (pas de fallback automatique) : si le binaire `ssh` manque
(Windows sans Git for Windows) ou la clé est invalide, le run s'arrête ; le message d'erreur
conseille alors de passer `transport: http` dans `config.yaml` pour utiliser HTTPS au
prochain lancement.

La référence complète des clés figure dans le § Quick start du [README](https://github.com/frack113/sigmacatch/blob/main/README.md#quick-start).
