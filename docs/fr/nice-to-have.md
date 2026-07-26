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

**État :** toutes les opérations git (clone, fetch, push) utilisent exclusivement HTTP(S) via `grit-lib` + `reqwest`. L'authentification est injectée en tant que `x-access-token` dans les URLs HTTPS. Pas de support SSH.

**Ce qui manque :**
- Couche de transport SSH pour clone/fetch/push (gestion des clés SSH, agent forwarding, ou auth basée sur clés)
- Option de config pour choisir entre HTTP+token et SSH
- `grit-lib` aurait besoin d'un backend transport SSH (actuellement HTTP-only)
- Vérification des clés SSH hôtes et gestion du known_hosts
- Résolution d'URL fork pour SSH (`git@github.com:user/sigma.git` au lieu de `https://github.com/user/sigma.git`)

**Cas d'usage :** environnements où les clés SSH sont préférées aux tokens (CI/CD avec deploy keys, environnements corporate avec accès SSH-only, pas de gestion de tokens).

---

## 7. Filtre de chargement des règles (status/level)

**État :** `SigmaFilterConfig` définit des seuils `min_status` (défaut : stable) et `min_level` (défaut : critical) dans `config.rs`, mais ceux-ci ne sont **jamais appliqués** lors du chargement dans `load_all_rules()`. Le filtre actuel ne vérifie que : produit Windows + skip set. Les docs décrivaient précédemment ceci comme implémenté — corrigé pour refléter le comportement réel.

**Ce qui manque :**
- Appliquer les filtres `min_status` et `min_level` dans `load_all_rules()` après le parsing de chaque règle
- Les règles sans champ status ou level doivent être acceptées (pass-through)
- Afficher le nombre de règles filtrées dans la table de démarrage
- Configurable via `config.yaml` → `sigma.min_status` et `sigma.min_level`

**Cas d'usage :** charger uniquement les règles de production (stable + critical/high) pour un évaluation plus rapide, ignorer les règles expérimentales/dépréciées/informationnelles dans les pipelines CI.
