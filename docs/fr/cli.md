# CLI — Diagnostic et sous-commandes

## `sigmacatch-check` — validation de la régression (cross-platform)

`check` n'est plus une sous-commande des binaires de collecte : c'est un binaire
standalone, **`sigmacatch-check`**, compilé pour Linux et Windows, sans collector. Il
charge les règles Sigma et les données de régression, rejoue chaque
event stocké dans le moteur de détection, et vérifie que la règle attendue matche encore.

**Usage :**

```text
sigmacatch-check [--json] [--ignore] [--fix] [--path <DIR>]
```

- `--json` — sortie en JSON au lieu du texte lisible.
- `--ignore` — saute les entrées invalides (entrée/données brutes absentes, events vides)
  sans les compter comme échecs.
- `--fix` — normalise les fins de ligne JSON et l'indentation `info.yml`.
- `--path <DIR>` — racine du repo sigma (défaut : `./sigma`).
- `--help`, `-h` — affiche l'usage et sort.

**Fonction :** validation approfondie de toutes les données de régression dans le
`regression_data/` de la racine sigma (`./sigma/regression_data` par défaut). Les
entrées sont parses selon leur `LogType` : `.evtx` via
`input_windows_evtx::parse_evtx_bytes`, `.log` via le parser auditd, lignes JSON directes.
Le logtype `Raw` est ignoré.

### Pipeline

1. Charge toutes les règles Sigma depuis la racine sigma (`./sigma` par défaut, `--path <DIR>` pour surcharger)
2. Construit le `DetectionEngine` une seule fois
3. Charge les entrées de régression depuis `<DIR>/regression_data`
4. Validation **bidirectionnelle** du `regression_tests_path` entre règles et entrées :
   chaque entrée doit correspondre à une règle déclarant ce chemin, et chaque chemin déclaré
   doit pointer vers une entrée existante (chemins manquants / incohérents comptés).
5. Pour chaque entrée `info.yml` :
   - Valide l'existence + non-vide (pas de vérification structurelle profonde à ce stade)
   - Charge le `.evtx` / `.log` brut, parse les events
   - Évalue les events contre la règle
   - Valide : la règle DOIT matcher (test de détection positive)
   - Quand un `.json` auxiliaire est présent, valide le `match_count` déclaré contre le
     nombre réel de hits (incohérence de match_count = échec)
6. Rapport pass/fail par règle + résumé (exit 1 en cas d'échec de détection ou de chemin)

### Sortie

```text
[PASS] 1 alert(s), rule matched
[PASS] 1 alert(s), rule matched
...
[FAIL] EMPTY — no events produced from raw data
[PASS] 1 alert(s), rule matched
...
[FAIL] RULE NOT MATCHED — expected '460479f3-80b7-42da-9c43-2cc1d54dbccd' (0 alert(s), matched: )

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          200
  Failed:          2
  Pass rate:       99.0%
============================================================
```

Le résumé affiche aussi, quand non nuls : `Missing paths`, `Mismatched`, `Ignored`,
`Skipped` et `Dropped lines`. Un résumé en échec sort avec exit 1 (échecs de détection
**ou** chemins manquants/incohérents).

**Exemple :**

```bash
sigmacatch-check
sigmacatch-check --json --ignore
# depuis la racine d'un checkout du repo sigma (ex. CI/CD sur SigmaHQ/sigma) :
sigmacatch-check --path .
sigmacatch-check --fix --path .
```

### Sortie JSON

`--json` produit :

```json
{
  "total": 202,
  "passed": 200,
  "skipped": 0,
  "ignored": 0,
  "missing_path": 0,
  "mismatched_path": 0,
  "failed_count": 2,
  "pass_rate": 99.0,
  "failed": [
    {
      "rule_name": "registry_event_add_local_hidden_user",
      "error": "RULE NOT MATCHED — expected '460479f3-...' (0 alert(s), matched: )"
    },
    {
      "rule_name": "cisco_cli_dot1x_disabled",
      "error": "EMPTY — no events produced from raw data"
    }
  ]
}
```

---

## Sous-commandes de diagnostic des binaires de collecte

Les commandes ci-dessous sont des sous-commandes des binaires, **toujours compilées**
(la feature `tools` a été supprimée) :

| Binaire | Sous-commandes |
|---|---|
| `sigmacatch-channel` (Windows) | `check-filter`, `list-rules` |
| `sigmacatch-linux` (Linux) | `check-filter`, `list-rules` |

Une sous-commande inconnue ou absente → le binaire démarre sa boucle de collecte normale.
Les équivalentes Linux partagent la même logique avec le filtre produit `linux`.

> **Prérequis commun :** chaque sous-commande charge `config.yaml` via `Config::load`, qui
> exécute la validation **complète** (git.author/email/token compris) — pas seulement la
> section `filter`. Sur une machine neuve avec le `config.yaml` par défaut, une
> sous-commande diagnostic peut donc échouer sur une erreur git avant d'atteindre son
> propre travail.

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

Les sous-commandes `get-atomic` et `check-channels` ont été retirées. `get-atomic` est
remplacé par la liste des techniques manquantes produite par `list-rules --json --coverage`
et la génération des données de régression ; les tests Atomic Red Team sont désormais
orchestrés directement sur la VM (module `Invoke-AtomicRedTeam` dans `C:\AtomicRedTeam`)
en ciblant les règles sans données. `check` est remplacé par le binaire standalone
`sigmacatch-check` (voir plus haut).
