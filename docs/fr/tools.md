# Outils

Outils de dev dans le crate `localcheck`, chacun avec sa propre fonction. Ils restent hors du
binaire principal `sigmacatch` pour garder son arbre de dépendances léger.

## check_evtx

**Fichier :** `localcheck/src/check_evtx.rs`

**Usage :** `cargo run --release --bin check_evtx`

**Fonction :** Batch validation du moteur de détection Sigma contre les données de régression SigmaHQ.

### Pipeline

1. Charge toutes les règles depuis `./sigma`, filtre sur Windows
2. Charge les entrées de régression depuis `./sigma/regression_data`
3. Construit le `DetectionEngine` une seule fois
4. Pour chaque entrée `info.yml` : charge le `.evtx` brut, le parse → events
5. Évalue les events contre la règle
6. Valide : la règle DOIT matcher (test de détection positive)
7. Rapport pass/fail par règle + résumé (exit 1 si échec)

### Sortie

```
  [  1/100] proc_creation_win_bitsadmin_download ... [PASS] 1 alert(s), rule matched
  [  2/100] win_security_foo  ... [FAIL] RULE NOT MATCHED — expected '<uuid>' (0 alert(s), matched: ...)

============================================================
  VALIDATION SUMMARY
============================================================
  Total rules:     100
  Passed:          95
  Failed:          5
  Pass rate:       95.0%
============================================================
```

### Exemple

```bash
cargo run --release --bin check_evtx
```

---

## check_filter

**Fichier :** `localcheck/src/check_filter.rs`

**Usage :** `cargo run --release --bin check_filter`

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

```
  product=windows status=None level=None author=Some("frack113")  →  461 loaded / 3769 total
    GT: loaded=461 prod=908 stat=0 lvl=0 auth=2400 total=3769
    filter: loaded=461 prod=908 stat=0 lvl=0 auth=2400 total=3769
    ✅ all dimensions match ground truth
```

### Exemple

```bash
cargo run --release --bin check_filter
```

---

## Comment ajouter un outil

1. Créer `localcheck/src/<name>.rs` avec un docstring en tête
2. Ajouter l'entrée dans `localcheck/Cargo.toml` :

```toml
[[bin]]
name = "<name>"
path = "src/<name>.rs"
```

3. Ajouter seulement les dépendances nécessaires à l'outil dans `localcheck/Cargo.toml`
4. Documenter ici avec usage et pipeline
