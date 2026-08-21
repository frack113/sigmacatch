# CLI — Sous-commandes de diagnostic

Les commandes de diagnostic sont disponibles sur `sigmacatch-channel` derrière la feature `tools`
(désactivée par défaut). Lisez `sigmacatch-channel --help` pour la liste complète.

## check

**Usage :** `sigmacatch-channel check [--json]`

**Fonction :** validation approfondie de toutes les données de régression dans `./sigma/regression_data`.

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
6. Exit 0 si succès (toutes les règles passent ou sont skipées)

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
      "rule_id": "460479f3-80b7-42da-9c43-2cc1d54dbccd",
      "error": "RULE NOT MATCHED — expected '460479f3-...' (0 alert(s), matched: )"
    }
  ]
}
```

---

## check-filter

**Usage :** `sigmacatch-channel check-filter [--json]`

**Fonction :** valide `SigmaFilterConfig` (product / status / level / author) contre le vrai jeu
de règles Sigma. Pas d'args CLI — exécute toutes les combinaisons de filtres automatiquement.

### Pipeline

1. Charge toutes les règles depuis `./sigma` une seule fois (`SigmahqRules::new()`)
2. Pour chaque combinaison de filtres : applique le filtre et lit `LoadStats`
3. Recalcule indépendamment les comptages ground-truth par dimension (`count_ground_truth`)
4. Compare chaque bucket : `loaded`, `product`, `status`, `level`, `author`, `total`
5. Rapport pass/fail par test + résumé (exit 1 si écart)

Ce n'est **pas circulaire** : les stats viennent de `filter()`, le ground truth est compté
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
les stats de couverture (règles avec régression locale, branches remote en attente, % de couverture).

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

## get-atomic

**Usage :** `sigmacatch-channel get-atomic [--output run_atomic.ps1] [--getprereqs] [--json]`

**Fonction :** génère un script `run_atomic.ps1` qui chaîne les commandes
`Invoke-AtomicTest T1xxx.xxx` pour les techniques ATT&CK des règles **sans
regression data** selon le filtre config. Le script est copié sur la VM Windows
et exécuté manuellement ; sigmacatch-channel (boucle continue) capte les events
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

- `Start-Sleep 30` entre les tests → laisse sigmacatch-channel collecter les events
- `-TimeoutSeconds 120` → évite qu'un test bloquant fige la chaîne
- Les règles sans tag `attack.*` sont comptées et listées dans le rapport (pas
  de `Invoke-AtomicTest` généré pour elles)

### Limitations

Pas de garantie de couverture : une règle avec une condition spécifique peut ne
pas matcher l'event produit par le test ART. Les règles restées sans data sont
re-listées au prochain run (le skip set n'exclut que ce qui est déjà généré).

### Exemple

```bash
sigmacatch-channel get-atomic
sigmacatch-channel get-atomic --output /tmp/run_atomic.ps1
sigmacatch-channel get-atomic --getprereqs --json
```
