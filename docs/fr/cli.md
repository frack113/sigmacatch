# CLI — Diagnostic et sous-commandes

## `regressiondata-check` — validation de la régression (cross-platform)

`check` n'est plus une sous-commande des binaires de collecte : c'est un binaire
standalone, **`regressiondata-check`**, compilé pour Linux et Windows, sans collector. Il
charge les règles Sigma et les données de régression, rejoue chaque
event stocké dans le moteur de détection, et vérifie que la règle attendue matche encore.

**Usage :**

```text
regressiondata-check [--json] [--ignore] [--fix] [--path <DIR>]
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
Le logtype `Raw` est sauté (compté dans `Skipped`).

### Pipeline

1. Charge toutes les règles Sigma depuis la racine sigma (`./sigma` par défaut, `--path <DIR>` pour surcharger)
2. Construit le `DetectionEngine` une seule fois en mode **lenient** (`new_lenient`) : les
   règles qui échouent à la compilation sont sautées avec un avertissement, jamais un échec
3. Charge les entrées de régression depuis `<DIR>/regression_data`
4. Validation **bidirectionnelle** du `regression_tests_path` entre règles et entrées :
   chaque entrée doit correspondre à une règle déclarant ce chemin, et chaque chemin déclaré
   doit pointer vers une entrée existante (chemins manquants / incohérents comptés).
5. Avertissements non bloquants : rule ids qui ne sont pas des UUID v4 (l'amont SigmaHQ en
   publie ; on avertit sans échouer) et règles non compilées (mode lenient)
6. Pour chaque entrée `info.yml` :
   - Valide l'`info.yml` : `rule_metadata` non vide (toujours un échec), indentation au
     style SigmaHQ 4 espaces, `regression_tests_info` non vide (vide → échec, ou ignoré
     avec `--ignore`)
   - Valide le `.json` auxiliaire s'il est présent : JSON **ou JSONL** (un objet par
     ligne) valide, exactement une fin de ligne
   - Charge la donnée brute selon le `logtype` (`.evtx`, `.log`, lignes JSON), parse les events
   - Évalue les events contre la règle
   - Valide : la règle DOIT matcher (test de détection positive)
   - Quand un `.json` auxiliaire est présent, valide le `match_count` déclaré contre le
     nombre réel de hits (incohérence de match_count = échec)
7. Rapport pass/fail par règle + résumé (exit 1 en cas d'échec de détection ou de chemin)

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
`Skipped`, `Dropped lines` et `Warnings`, suivi de la liste `Failed rules`
(`FAIL <rule_name> — <error>`) quand des entrées ont échoué. Un résumé en échec sort
avec exit 1 (échecs de détection **ou** chemins manquants/incohérents).

**Exemple :**

```bash
regressiondata-check
regressiondata-check --json --ignore
# depuis la racine d'un checkout du repo sigma (ex. CI/CD sur SigmaHQ/sigma) :
regressiondata-check --path .
regressiondata-check --fix --path .
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
  ],
  "warning_count": 1,
  "warnings": [
    "1 rule(s) failed to compile (lenient mode): [7]"
  ]
}
```

Les `warnings` regroupent les rule ids non-v4 et les règles non compilées (mode lenient) ;
elles n'entraînent jamais l'exit 1.

---

## `sigmacatch-evtx` — générateur de régression EVTX statique (run unique)

Binaire **non-live** autonome (feature `evtx` dans `sigmacatch-win`) : il scanne
récursivement un dossier pour des fichiers `.evtx`, parse chaque event en pur Rust, les
pousse à travers le moteur de détection, écrit les données de régression SigmaHQ pour chaque
règle matchée (writer EVTX pur Rust — jamais `EvtExportLog`, car les events statiques ne sont
pas dans le journal d'événements live), puis commit et push par règle vers `sigmacatch/<date>`
sur le fork configuré. Il se termine après une passe : lecture → détection → génération →
commit/push, sans boucle de collecte.

**Utilisation :**

```text
sigmacatch-evtx [OPTIONS]

      --evtx <EVTX_PATH>  Dossier de fichiers .evtx, scanné récursivement
                       (défaut : C:\Windows\System32\winevt\Logs)
      --config <CONFIG>   Chemin vers config.yaml (défaut : config.yaml)
  -v, --verbose        Journalisation info sur stderr
  -h, --help           Affiche l'aide et quitte
```

Le repo sigma et la sortie de régression proviennent de la config
(`git.sigma_repo_path`, chemins relatifs résolus depuis le dossier du fichier de config) ;
les données de régression sont écrites sous `<sigma_repo_path>/regression_data`.

---

## Flags des binaires de collecte

Les binaires `sigmacatch-channel`, `sigmacatch-linux`, `sigmacatch-linux-sysmon` et
`sigmacatch-linux-ebpf` partagent les mêmes flags (parsing commun) :

```text
sigmacatch [OPTIONS]

  -a, --all-rules     Charge toutes les règles (ignore les données de régression existantes)
  -c, --contrib       Active le push sur le fork (neutralisé par --offline)
  -o, --offline       Aucune opération git (fichiers sur disque tels quels, pas de commit/push)
  -r, --max-runs <N>  Quitte après N cycles de collecte (0 = illimité)
  -v, --verbose       Journalisation info sur stderr
  -n, --dry-run       Vérification en lecture seule : charge les règles de ./sigma et
                      construit le moteur — aucune donnée écrite, aucune opération git/réseau
      --author <NOM>  Remplace l'auteur git du config.yaml pour ce run
  --help, -h          Affiche l'aide et quitte
```

`--dry-run` s'exécute **avant** l'initialisation du logger : il ne crée ni `config.yaml`
ni `logs/`, saute la validation git (author/email/token) et se limite au chargement des
règles de `./sigma` + à la construction du moteur de détection.

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
`regressiondata-check` (voir plus haut).
