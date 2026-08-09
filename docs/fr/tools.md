# Outils

Outils de dev dans le crate `tools`, chacun avec sa propre fonction. Ils restent hors du
binaire principal `sigmacatch` pour garder son arbre de dépendances léger.

## check_evtx

**Fichier :** `tools/src/check_evtx.rs`

**Usage :** `cargo run --release --bin check_evtx [--json]`

**Fonction :** Batch validation du moteur de détection Sigma contre les données de régression SigmaHQ.

### Pipeline

1. Charge toutes les règles Sigma depuis `./sigma`, filtre sur Windows
2. Construit le `DetectionEngine` une seule fois
3. Charge les entrées de régression depuis `./sigma/regression_data`
4. Pour chaque entrée `info.yml` : charge le `.evtx` brut, le parse → events
5. Évalue les events contre la règle
6. Valide : la règle DOIT matcher (test de détection positive)
7. **Vérification de conformité JSON** : quand un `<rule_id>.json` committé existe, vérifie que
   `parse_winevt_xml_raw` le reproduit à l'identique (compatibilité du format SigmaHQ) — un écart
   est rapporté séparément et ne fait pas échouer le test de détection
8. Rapport pass/fail par règle + résumé (exit 1 en cas d'échec de détection)

### Sortie

```text
Found 3777 total rules
  → 2872 windows rules after filtering

Found 202 regression entry(ies)

Engine ready — 2872 rule(s) loaded.

Running validation...

  [   1/202 ] win_security_explicit_credential_local_logon       ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[PASS] 1 alert(s), rule matched
  [   2/202 ] win_security_susp_scheduled_task_delete_or_disable ...     [JSON MISMATCH] no EVTX record reproduces committed JSON first diff: Event.EventData.TaskContent ...
[PASS] 1 alert(s), rule matched
  ...
  [ 165/202 ] registry_event_add_local_hidden_user               ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[FAIL] RULE NOT MATCHED — expected '460479f3-80b7-42da-9c43-2cc1d54dbccd' (0 alert(s), matched: )
  --- explain_rule trace ---
  ...
  [ 201/202 ] win_defender_exploit_redsun_tiering_engine_detected_as_eicar ... [JSON MISMATCH] ...
[PASS] 1 alert(s), rule matched
  [ 202/202 ] image_load_win_werfaultsecure_dbgcore_dbghelp_load ...     [JSON OK] parse_winevt_xml_raw reproduces committed JSON
[PASS] 1 alert(s), rule matched

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          201
  Skipped:         0
  Failed:          1
  Pass rate:       99.5%

  JSON FORMAT CHECKS (parse_winevt_xml_raw vs committed JSON):
  Checked:         189
  Matched:         186
  Mismatch:        3
============================================================

Failed rules:
  FAIL registry_event_add_local_hidden_user — RULE NOT MATCHED — expected '460479f3-...'

JSON format mismatches:
  MISMATCH win_security_susp_scheduled_task_delete_or_disable — no EVTX record reproduces committed JSON first diff: Event.EventData.TaskContent ... (CRLF vs LF dans le XML embarqué)
  MISMATCH proc_creation_win_susp_right_to_left_override — no EVTX record reproduces committed JSON first diff: Event.System.TimeCreated.#attributes.SystemTime ... (précision des fractions de seconde)
  MISMATCH win_defender_exploit_redsun_tiering_engine_detected_as_eicar — no EVTX record reproduces committed JSON first diff: Event.EventData.Threat ID (nombre vs string)
```

Le run `check_evtx` ci-dessus correspond à l'état actuel de `sigma/regression_data`
(202 entrées, 201 PASS / 1 FAIL — l'échec `registry_event_add_local_hidden_user` est le problème
registry connu en attente d'une maj rsigma ; 3 écarts de format JSON cosmétiques restent).

### Exemple

```bash
cargo run --release --bin check_evtx
```

---

## check_filter

**Fichier :** `tools/src/check_filter.rs`

**Usage :** `cargo run --release --bin check_filter [--json]`

**Fonction :** Valide `SigmaFilterConfig` (product / status / level / author) contre le vrai jeu
de règles Sigma. Pas d'args CLI — exécute toutes les combinaisons de filtres automatiquement.

### Pipeline

1. Charge toutes les règles depuis `./sigma` une seule fois (`SigmahqRules::new()`)
2. Pour chaque combinaison de filtres : applique le filtre et lit `LoadStats`
3. Recalcule indépendamment les comptages ground-truth par dimension (`count_ground_truth`)
4. Compare chaque bucket : `loaded`, `product`, `status`, `level`, `author`, `total`
5. Rapport pass/fail par test + résumé (exit 1 si écart)

Ce n'est **pas circulaire** : les stats viennent de `filter()`, le ground truth est compté
directement depuis les règles brutes — donc un `stats()` auto-cohérent mais faux échouerait quand même.

### Sortie

```text
Loaded 3777 total rules from ./sigma

============================================================
  TEST: empty filter (no filtering)
============================================================
  product=windows status=None level=None author=None  →  2872 loaded / 3777 total
    GT: loaded=2872 prod=905 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=2872 prod=905 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: product filter
============================================================
  product=linux status=None level=None author=None  →  248 loaded / 3777 total
    GT: loaded=248 prod=3529 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=248 prod=3529 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  product=macos status=None level=None author=None  →  75 loaded / 3777 total
    GT: loaded=75 prod=3702 stat=0 lvl=0 auth=0 total=3777  sum=3777
    filter: loaded=75 prod=3702 stat=0 lvl=0 auth=0 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: author filter
============================================================
  product=windows status=None level=None author=Some("FRACK113")  →  461 loaded / 3777 total
    GT: loaded=461 prod=905 stat=0 lvl=0 auth=2411 total=3777  sum=3777
    filter: loaded=461 prod=905 stat=0 lvl=0 auth=2411 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  TEST: combined: with author
============================================================
  product=windows status=None level=None author=Some("Elastic")  →  5 loaded / 3777 total
    GT: loaded=5 prod=905 stat=0 lvl=0 auth=2867 total=3777  sum=3777
    filter: loaded=5 prod=905 stat=0 lvl=0 auth=2867 total=3777  sum=3777
    ✅ all dimensions match ground truth
  ✅ PASS

============================================================
  SUMMARY
============================================================
  Passed: 7
  Failed: 0
============================================================
```

(7 tests : empty filter, product, status, level, author, combined product+status+level, combined
avec author — tous passent au moment de la rédaction, 3777 règles totales.)

### Exemple

```bash
cargo run --release --bin check_filter
```

---

## check_dry_run

**Fichier :** `tools/src/check_dry_run.rs`

**Usage :** `cargo run --release --bin check_dry_run [--json]`

**Fonction :** diagnostics git de l'ancien flag `--dry-run` de sigmacatch (déplacé ici pour
simplifier le binaire principal). Réutilise `Config::load_with_cli` + `dry_run_git` de
`sigmacatch-config`. Accepte les mêmes flags que le binaire principal (`--author`, `--offline`,
`--contrib`, `--help`).

### Pipeline

1. `parse_args()` + `Config::load_with_cli("config.yaml", cli)`
2. `dry_run_git(&config)` → résolution du token (config + env), détection du fork (HTTP HEAD),
   vérification API `/user`, endpoint git smart HTTP info/refs, état du repo local `sigma/`
3. Rapport détaillé de chaque étape → identifier le point de défaillance

---

## check_channels

**Fichier :** `tools/src/check_channels.rs`

**Usage :** `cargo run --release --bin check_channels [--json]`

**Fonction :** résout et liste les channels Windows que le moteur collecterait (ancien
`--channels-only` de sigmacatch, déplacé ici).

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. `DetectionEngine::new(&rules)` → `resolve_channels(&custom_map)` (incl. custom_channels.yaml)
4. Affiche la liste des channels (exit 1 si aucun)

---

## list_rules

**Fichier :** `tools/src/list_rules.rs`

**Usage :** `cargo run --release --bin list_rules [--json]`

**Fonction :** liste les règles chargées avec leur chemin (ancien `--list-rules` de sigmacatch,
déplacé ici).

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. Pour chaque règle : id, titre, status, niveau, techniques (tags `attack.*`), chemin, lien ART
   (première sous-technique)

---

## get_atomic

**Fichier :** `tools/src/get_atomic.rs`

**Usage :** `cargo run --release --bin get_atomic [--output run_atomic.ps] [--getprereqs] [--json]`

**Fonction :** génère un script `run_atomic.ps1` qui chaîne les commandes
`Invoke-AtomicTest T1xxx.xxx` pour les techniques ATT&CK des règles **sans
regression data** selon le filtre config. Le script est copié sur la VM Windows
et exécuté manuellement ; sigmacatch (boucle continue) capte les events
générés et produit la regression data.

### Pipeline

1. `Config::load("config.yaml")` (section filter + `git.sigma_repo_path`)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. Skip set = règles avec regression data déjà valide (local `regression_data/`)
   ∪ ids des branches remote `sigmacatch/*` en attente de merge
4. Pour chaque règle restante : `rule.attack_techniques()` (extension trait
   `SigmaRuleExt` de `sigmacatch-rule`)
5. Dédupe + tri des techniques (BTreeSet) — une `Invoke-AtomicTest` par technique
6. Écrit `run_atomic.ps1` (ou `--output <path>`) + rapport

### Script généré

```powershell
$ErrorActionPreference = "Continue"
Import-Module Invoke-AtomicRedTeam
# 12 rule(s) without regression data — 7 technique(s)
Start-Sleep -Seconds 5
Invoke-AtomicTest T1055.001 -TimeoutSeconds 120
Start-Sleep -Seconds 30
Invoke-AtomicTest T1547.001 -TimeoutSeconds 120
...
```

- `Start-Sleep 30` entre les tests → laisse sigmacatch collecter les events
- `-TimeoutSeconds 120` → évite qu'un test bloquant fige la chaîne
- Les règles sans tag `attack.*` sont comptées et listées dans le rapport (pas
  de `Invoke-AtomicTest` généré pour elles)

### Limitations

Pas de garantie de couverture : une règle avec une condition spécifique peut ne
pas matcher l'event produit par le test ART. Les règles restées sans data sont
re-listées au prochain run (le skip set n'exclut que ce qui est déjà généré).

---

## channel_health

**Fichier :** `tools/src/channel_health.rs`

**Usage :** `cargo run --release --bin channel_health [--json] [--channel <name>]`

**Fonction :** diagnostic Windows-only pour vérifier la santé des channels Winevt (compteur
d'events, dernier event, statut). Sur non-Windows : stub JSON.

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge les règles Sigma depuis `./sigma` + filtre config
3. `DetectionEngine::new(&rules)` → `resolve_channels(&custom_map)`
4. Pour chaque channel : `EvtOpenChannelEnum` + `EvtQuery` (échantillon 1000 events max)
5. Rapport JSON/texte (exit 1 si aucun channel)

---

## coverage

**Fichier :** `tools/src/coverage.rs`

**Usage :** `cargo run --release --bin coverage`

**Fonction :** statistiques de couverture globale pour la config filtre actuelle.
Sortie JSON : règles totales, rules avec régression locale, rules en attente sur
branches remote, pourcentage de couverture.

### Pipeline

1. `Config::load("config.yaml")` (section filter)
2. Charge toutes les règles Sigma depuis `./sigma` + filtre config
3. Scan local `regression_data/` → skip set
4. `SigmaRepo::pending_regression_rule_ids()` → skip set branches remote
5. Calcul % couverture → JSON

---

## Comment ajouter un outil

1. Créer `tools/src/<name>.rs` avec un docstring en tête
2. Ajouter l'entrée dans `tools/Cargo.toml` :

```toml
[[bin]]
name = "<name>"
path = "src/<name>.rs"
```

1. Ajouter seulement les dépendances nécessaires à l'outil dans `tools/Cargo.toml`
2. Documenter ici avec usage et pipeline
