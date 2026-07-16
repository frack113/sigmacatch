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
- Le moteur Sigma évalue déjà les rules Linux, mais sans events它们 ne matchent jamais
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
