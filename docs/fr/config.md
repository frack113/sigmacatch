# Configuration

`sigmacatch` lit sa configuration dans un fichier unique `config.yaml` du
dossier de travail (CWD). Au premier lancement, un fichier est créé avec des
valeurs par défaut provisoires et le run s'arrête (`exit 1`) jusqu'à ce que vous
le modifiiez. Chaque section et chaque champ sont optionnels dans le fichier —
une section ou un champ manquant retombe sur sa valeur par défaut. Les champs
inconnus sont rejetés.

## Référence complète

```yaml
git:
  author: "sigmacatch"          # PLACEHOLDER — remplacez par votre nom d'utilisateur GitHub avant le run suivant
  email: ""                     # requis (toute valeur non vide contenant @)
  github_token: ""              # token GitHub (ou variable d'environnement GITHUB_TOKEN) — voir validation
  transport: http               # http ou ssh
  ssh_key_path: ""              # chemin absolu vers une clé privée SSH (uniquement avec transport: ssh)
  sigma_repo_url: "https://github.com/SigmaHQ/sigma.git"
  sigma_repo_path: "sigma"      # chemin du clone local ; les chemins relatifs se résolvent depuis le dossier du config
  offline: false                # true = zéro opération git (pas de pull/clone/commit/push)
  contrib: false                # true = pousser les commits vers votre fork distant
  working_branch: ""            # branche de travail optionnelle ; défaut sigmacatch/<AAAAJJMM>
  shallow_clone: true           # clone initial depth=1 (rapide), unshallow avant push (défaut true)
  sparse_checkout: true         # sparse checkout mode cône : rules/, rules-emerging-threats/, regression_data/ (défaut true)
  partial_clone: false          # filtre blobless (--filter=blob:none) pour le clone initial (défaut false)
  clone_timeout_secs: 600       # timeout global du clone (secondes)
  fetch_timeout_secs: 300       # timeout fetch/pull (secondes)
  http_timeout_secs: 120        # timeout HTTP par requête (secondes)
  max_retries: 3                # max tentatives de retry pour échecs transitoires
log:
  level_file: debug             # debug | info | warn | error
filter:
  product: windows              # windows | linux | macos (vide = pas de filtre)
  # min_status: stable          # ne garder que les règles avec un status >= cette valeur (valeurs ci-dessous)
  # min_level: critical         # ne garder que les règles avec un level >= cette valeur (valeurs ci-dessous)
  author: ""                    # ne garder que les règles de cet author (vide = pas de filtre)
  max_rule_size: 1048576        # octets ; plage 1024..10MB
regression:
  max_failed_cycles: 3          # bloquer une règle après N cycles d'échec consécutifs
  add_json_output: false        # écrire aussi le <rule_id>.json auxiliaire à côté du fichier de données
hir_cache: ""                   # chemin vers le fichier de cache HIR persistant (warm-start moteur ; vide = recompilation à chaque run)
stop_file: ".sigmacatch.stop"   # créez ce fichier pour arrêter proprement un run continu (-r 0)
```

## git

| Clé | Défaut | Description |
|---|---|---|
| `author` | `sigmacatch` | Nom d'utilisateur GitHub. Le placeholder `sigmacatch` est rejeté ; alphanumérique + tirets uniquement. Requis sauf `offline: true`. |
| `email` | `""` | Email de commit. Doit contenir `@`. Requis sauf `offline: true`. |
| `github_token` | `""` | Token GitHub, ou variable d'environnement `GITHUB_TOKEN`. Requis pour `transport: http` quand une opération réseau est active (`offline: false` ou `contrib: true`). Pas d'espaces. |
| `transport` | `http` | Transport git : `http` ou `ssh`. |
| `ssh_key_path` | *(défaut)* | Chemin absolu vers une clé privée SSH (ed25519). Uniquement avec `transport: ssh` ; doit exister et être un fichier quand une opération réseau est active. `chmod 600` recommandé. |
| `sigma_repo_url` | `https://github.com/SigmaHQ/sigma.git` | Dépôt SigmaHQ à cloner/récupérer. |
| `sigma_repo_path` | `sigma` | Chemin du clone local. Les chemins relatifs se résolvent depuis le dossier du fichier de configuration ; ne doit pas être vide ni contenir `..`. |
| `offline` | `false` | Ignore toutes les opérations git (pas de pull/clone/commit/push). Les fichiers sur disque sont utilisés tels quels (`.git` optionnel). **Neutralise `contrib`** (forcé à `false`). |
| `contrib` | `false` | Pousse les commits vers votre fork distant. Neutralisé par `offline: true`. |
| `working_branch` | *(défaut)* | Nom de la branche de travail. Quand vide, la branche par défaut `sigmacatch/<AAAAJJMM>` est utilisée. |
| `shallow_clone` | `true` | Clone initial depth=1 (rapide), unshallow avant push. Mettre `false` pour historique complet. |
| `sparse_checkout` | `true` | Sparse checkout mode cône : rules/, rules-emerging-threats/, regression_data/. `false` = worktree complet. |
| `partial_clone` | `false` | Filtre blobless (`--filter=blob:none --depth=1`) pour le clone initial. Nécessite le CLI git. Repli sur shallow clone avec avertissement. |
| `clone_timeout_secs` | `600` | Timeout global du clone en secondes. Doit être >0 et ≤3600. |
| `fetch_timeout_secs` | `300` | Timeout fetch/pull en secondes. Doit être >0 et ≤1800. |
| `http_timeout_secs` | `120` | Timeout HTTP par requête en secondes. Doit être >0 et ≤600. |
| `max_retries` | `3` | Max tentatives de retry pour échecs transitoires. Doit être ≤10. |

## log

| Clé | Défaut | Description |
|---|---|---|
| `level_file` | `debug` | Niveau de log fichier : `debug`, `info`, `warn`, `error`. |

## filter

Tous les filtres sont optionnels ; non défini = pas de filtrage.

| Clé | Défaut | Description |
|---|---|---|
| `product` | `windows` | Produit SigmaHQ à garder : `windows`, `linux` ou `macos` (réservé, aucun collecteur pour l'instant). Vide = pas de filtre produit. |
| `min_status` | *(défaut)* | Ne garder que les règles dont le status est à ce niveau ou au-dessus : `unsupported` < `deprecated` < `experimental` < `test` < `stable`. |
| `min_level` | *(défaut)* | Ne garder que les règles dont le level est à ce niveau ou au-dessus : `informational` < `low` < `medium` < `high` < `critical`. |
| `author` | *(défaut)* | Ne garder que les règles de cet author (normalisé). |
| `max_rule_size` | `1048576` | Rejette les règles dont le YAML dépasse ce nombre d'octets. Plage 1024..10485760 (10MB). |

> Définir `min_status` à `stable` ou `min_level` à `high`/`critical` est très
> restrictif et déclenche un avertissement au démarrage.

## regression

| Clé | Défaut | Description |
|---|---|---|
| `max_failed_cycles` | `3` | Après N cycles de capture d'échec consécutifs, une règle est bloquée (loggée, retirée du skip set, plus de re-capture). Min 1. |
| `add_json_output` | `false` | Écrit aussi le `<rule_id>.json` auxiliaire (événement brut) à côté du fichier de données. Voir [Format de Sortie](output-format.md). |

## hir_cache

| Clé | Défaut | Description |
|---|---|---|
| `hir_cache` | `""` | Chemin vers un fichier de cache HIR persistant. Quand défini, le moteur de détection compilé est persisté après chaque changement de règle et warm-starté au run suivant, sautant la recompilation des règles. Vide = recompilation à chaque run. Peut aussi être défini via le flag CLI `--hir-cache <CHEMIN>`. |

## stop_file

`stop_file` nomme un fichier de contrôle (défaut `.sigmacatch.stop`, relatif au
dossier de travail). Tant que le fichier existe, un run continu (`-r 0`) effectue
une arrêt propre — drain, flush, commit — au prochain poll, pour arrêter un run en
direct sans kill brutal. Supprimez le fichier pour continuer.
