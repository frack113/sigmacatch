# Nice-to-have — Fonctionnalités à venir

Fonctionnalités identifiées comme utiles mais hors périmètre actuel. Pas de planning — documentées pour référence.

---

## 1. Mode offline

**État :** non implémenté. L'app clone/pull toujours depuis GitHub au démarrage.

**Ce qui manque :**
- Flag `--offline` pour utiliser le repo sigma/ existant sans fetch réseau
- Bundle de règles SigmaHQ embarqué dans le binaire (via `include_bytes!` ou fichier shippe avec le release)
- Pas de dépendance réseau du tout — le binaire fonctionne sur une machine isolée (air-gapped)

**Cas d'usage :** environnements classified/isolés, CI sans accès réseau, tests reproductibles.

---

## 2. Mode sans contrib

**État :** contrib est maintenant **toujours actif** — fork detection, branch, commit, push tournent à chaque run. L'option `contrib` a été supprimée de la config.

**Ce qui manque :**
- Option `--no-contrib` ou config pour désactiver le workflow contrib (clone upstream local uniquement)
- Le `regression_tests_path` est quand même ajouté aux fichiers YAML des règles — pourrait être optionnel

**Cas d'usage :** usage interne, audit de rules, génération de données sans intention de contribuer.

---

## 3. Support Linux

**État :** le collector est un stub (`Vec vide`) — la pipeline tourne end-to-end pour les tests, mais ne collecte rien.

**Ce qui manque :**
- Collecteur d'événements Linux : `journald` (systemd), `syslog`, ou `auditd`
- Mapping logsource Sigma → canaux Linux (les règles SigmaHQ ont des `logsource.product: linux`)
- Le moteur Sigma évalue déjà les rules Linux, mais sans events elles ne matchent jamais
- Corrélation possible avec des outils comme `osquery`, `auditd`, ou `falco`

**Cas d'usage :** serveurs Linux, conteneurs, environnements cloud.

---

## 4. Support Correlation V2

**État :** le moteur `rsigma-eval` supporte les rules V2 (correlation), mais la pipeline ne les gère pas explicitement.

**Ce qui manque :**
- Les rules de corrélation (`correlation` type dans Sigma V2) nécessitent de garder en mémoire plusieurs events avant de décider
- La pipeline actuelle évalue chaque event individuellement — pas de buffer temporel
- Il faudrait un stateful evaluator qui accumule les events par `correlation_rule` et déclenche quand les conditions sont réunies
- Gestion des fenêtres temporelles (`timespan`) et des seuils (`field` count)

**Cas d'usage :** détection d'attaques multi-étapes, bruteforce, anomalies comportementales.

---

## 5. Optimiser DetectionEngine

**État :** l'engine actuel charge toutes les rules dans `rsigma-eval` `Engine`, puis évalue chaque event contre l'ensemble des rules en une seule boucle.

**Ce qui manque :**
- Indexer les rules par `logsource` (product, service, category) pour éviter de charger les rules non pertinentes
- Pré-filtrage par event : seulement push dans le moteur les events dont le logsource matche au moins une rule chargée
- Table de lookup rapide : metadata des rules → logsource keys, construite avant la création de l'engine
- `rsigma-eval` V2 pipeline : `rsigma-eval 0.30` supporte `set_pipeline` pour switcher les pipelines dynamiquement — router les events vers des engines spécialisés (ex. Sysmon-only, network-only)
- Évaluation parallèle : `rayon` ou `crossbeam` pour distribuer les events sur plusieurs instances d'engine pendant `process_events`
- Caching de compilation des rules : éviter de recompiler la même rule pour chaque event — utiliser le caching interne de `rsigma-eval`

**Cas d'usage :** cycles d'évaluation plus rapides avec des centaines de règles Sigma, empreinte mémoire réduite par évitement du chargement de rules inutiles.

---

## 6. Transport Git SSH

**État :** ✅ implémenté. Configurable via `config.yaml` → `git.transport` (`http` ou `ssh`).

**Implémentation :**
- Enum `GitTransport` : `Http` (défaut) ou `Ssh`
- Struct `GitConfig` : `transport` + `ssh_key_path: Option<String>`
- `get_ssh_shell_command()` résout la commande SSH par priorité : `GIT_SSH_COMMAND` env > `GIT_SSH` env > `ssh_key_path` config > `ssh` par défaut
- `get_ssh_command()` construit `ssh -i <key>` quand un chemin de clé est fourni
- `fetch_remote_ssh()` : crée `SshTransport::with_shell_command()`, fetch via `grit_lib::fetch::fetch_remote()`
- `push_branch_ssh()` : push via `SshTransport::with_shell_command()` avec `grit_lib::push::push_remote()`
- `https_to_ssh_url()` : convertit `https://github.com/user/sigma.git` → `git@github.com:user/sigma.git`
- `git_clone_ssh()`, `git_pull_ssh()`, `git_push_ssh()` dans `repo.rs` dispatch les opérations SSH
- `SigmaRepo` porte `git_config` et dispatch clone/fetch/push selon `GitTransport`
- `github_token` est **optionnel** quand `transport: ssh` — validation skipée dans `Config::validate()`
- `~/.ssh/config` doit avoir `IdentityFile` pour `github.com` pour la résolution automatique de clés

**Limitations :**
- `push_remote` via SSH est limité au protocole v0/v1 (GitHub supporte ça pour les forks)
- Pas de gestion `known_hosts` — repose sur `ssh -o StrictHostKeyChecking` ou comportement SSH par défaut
- `git config --global user.name` et `user.email` doivent être configurés pour les commits
- La détection de fork utilise toujours HTTP HEAD

**Exemple de config :**
```yaml
git:
  transport: ssh
  ssh_key_path: "/home/user/.ssh/id_sigmacatch"
```


