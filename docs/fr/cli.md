# CLI — Sous-commandes de diagnostic

Les commandes de diagnostic sont des sous-commandes des binaires, derrière la feature `tools`
(désactivée par défaut) :

| Binaire | Sous-commandes |
|---|---|
| `sigmacatch-channel` (Windows) | `check`, `check-filter`, `check-channels`, `list-rules` |
| `sigmacatch-linux` (Linux) | `check`, `check-filter`, `list-rules` |

Une sous-commande inconnue ou absente → le binaire démarre sa boucle de collecte normale.
Les sections ci-dessous documentent les sous-commandes Windows ; les équivalentes Linux
(`check`, `check-filter`, `list-rules`) partagent la même logique avec le filtre produit
`linux` et la validation `.log`.

> **Prérequis commun :** chaque sous-commande charge `config.yaml` via `Config::load`, qui
> exécute la validation **complète** (git.author/email/token compris) — pas seulement la
> section `filter`. Sur une machine neuve avec le `config.yaml` par défaut, une
> sous-commande diagnostic peut donc échouer sur une erreur git avant d'atteindre son
> propre travail.

## check

**Usage :** `sigmacatch-channel check [--json]` / `sigmacatch-linux check [--json]`

**Fonction :** validation approfondie de toutes les données de régression dans `./sigma/regression_data`.

**Variante Linux :** le `check` Linux auto-détecte le format des données de chaque entrée
de régression depuis sa première ligne non vide : XML Sysmon-for-Linux (`sysmon`),
syslog RFC3164 (`syslog`) ou records auditd (`auditd`). Il parse ensuite les events en
conséquence avant évaluation.

### Pipeline

1. Charge toutes les règles Sigma depuis `./sigma`, filtre sur Windows
2. Construit le `DetectionEngine` une seule fois
3. Charge les entrées de régression depuis `./sigma/regression_data`
4. Pour chaque entrée `info.yml` :
   - Valide l'existence + non-vide (pas de vérification structurelle profonde à ce stade)
   - Charge le `.evtx` / `.log` brut, parse les events
   - Évalue les events contre la règle
   - Valide : la règle DOIT matcher (test de détection positive)
5. Rapport pass/fail par règle + résumé (exit 1 en cas d'échec de détection)
6. Exit 0 si succès (toutes les règles passent ou sont ignorées)

### Sortie

```text
Found 3777 total rules
  → 2872 windows rules after filtering

Found 202 regression entry(ies)

Engine ready — 2872 rule(s) loaded.

Running validation...

  [   1/202 ] win_security_explicit_credential_local_logon       ... [PASS] 1 alert(s), rule matched
  [   2/202 ] win_security_susp_scheduled_task_delete_or_disable ... [PASS] 1 alert(s), rule matched
  ...
  [ 165/202 ] registry_event_add_local_hidden_user               ... [FAIL] RULE NOT MATCHED — expected '460479f3-...'
  ...

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          201
  Skipped:         0
  Failed:          1
  Pass rate:       99.5%
============================================================
```

### Sortie JSON

`--json` produit :

```json
{
  "total": 202,
  "passed": 201,
  "skipped": 0,
  "failed_count": 1,
  "pass_rate": 99.5,
  "failed": [
    {
      "rule_name": "registry_event_add_local_hidden_user",
      "error": "RULE NOT MATCHED — expected '460479f3-...' (0 alert(s), matched: )"
    }
  ]
}
```

---

## check-filter

**Usage :** `sigmacatch-channel check-filter [--json]`

**Fonction :** valide `SigmaFilterConfig` (product / status / level / author) contre le vrai jeu
de règles Sigma. Aucun argument CLI — exécute toutes les combinaisons de filtres automatiquement.

### Pipeline

1. Charge toutes les règles depuis `./sigma` une seule fois (`SigmahqRules::new()`)
2. Pour chaque combinaison de filtres : applique le filtre et lit `LoadStats`
3. Recalcule indépendamment les comptages ground-truth par dimension (`count_ground_truth`)
4. Compare chaque bucket : `loaded`, `product`, `status`, `level`, `author`, `total`
5. Rapport pass/fail par test + résumé (exit 1 si écart)

Ce n'est **pas circulaire** : les stats viennent de `filter()`, le ground-truth est compté
directement depuis les règles brutes — donc un `stats()` auto-cohérent mais faux échouerait quand même.

### Exemple

```bash
sigmacatch-channel check-filter
```

---

## check-channels

**Usage :** `sigmacatch-channel check-channels [--json]`

**Fonction :** résout et liste les channels Windows que le moteur collecterait.

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. `DetectionEngine::new(&rules)` → `resolve_channels(&custom_map)` (incl. custom_channels.yaml)
4. Affiche la liste des channels (exit 1 si aucun)

### Exemple

```bash
sigmacatch-channel check-channels
```

---

## list-rules

**Usage :** `sigmacatch-channel list-rules [--json] [--coverage]`

**Fonction :** liste les règles chargées avec leur chemin. Avec `--coverage`, affiche aussi
le ratio de règles ayant des données de régression locale (`with_data / total`, pas un
pourcentage) ; les ids des branches remote `sigmacatch/*` en attente sont comptés dans le
skip set sans être listés séparément.

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. Pour chaque règle : id, titre, status, niveau, techniques (tags `attack.*`), chemin, lien ART
   (première sous-technique)

### Exemple

```bash
sigmacatch-channel list-rules
sigmacatch-channel list-rules --json --coverage
```

---

La sous-commande `get-atomic` a été retirée (remplacée par la liste des techniques
manquantes produite par `list-rules --json --coverage`, et la génération des données
de régression), les tests Atomic Red Team étant désormais orchestrés directement sur
la VM (module `Invoke-AtomicRedTeam` dans `C:\AtomicRedTeam`) en ciblant les règles
sans données.
