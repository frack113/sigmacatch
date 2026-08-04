# Outils

Outils de dev dans le crate `localcheck`, chacun avec sa propre fonction. Ils restent hors du
binaire principal `sigmacatch` pour garder son arbre de dépendances léger.

## check_evtx

**Fichier :** `localcheck/src/check_evtx.rs`

**Usage :** `cargo run --release --bin check_evtx`

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

```
  [  1/202] proc_creation_win_bitsadmin_download ... [PASS] 1 alert(s), rule matched
  [  2/202] win_security_foo  ... [FAIL] RULE NOT MATCHED — expected '<uuid>' (0 alert(s), matched: ...)

============================================================
  VALIDATION SUMMARY
============================================================
  Total entries:   202
  Passed:          196
  Skipped:         0
  Failed:          6
  Pass rate:       97.0%

  JSON FORMAT CHECKS (parse_winevt_xml_raw vs committed JSON):
  Checked:         202
  Matched:         199
  Mismatch:        3
============================================================
```

Le run `check_evtx` ci-dessus correspond à l'état actuel de `sigma/regression_data`
(202 entrées, 196 PASS / 6 FAIL — les 6 échecs sont le problème registry connu en attente d'une
maj rsigma ; 3 écarts de format JSON cosmétiques restent).

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
