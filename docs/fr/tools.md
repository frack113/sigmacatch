# Outils

Binaires secondaires en dehors du binaire principal (`sigmacatch`), chacun avec sa propre fonction.

## evtx_check

**Fichier :** `sigmacatch/src/bin/evtx_check.rs`

**Usage :** `cargo run --release --bin evtx_check <sigmahq_dir>`

**Fonction :** Batch validation du moteur de détection Sigma contre les données de régression SigmaHQ.

### Pipeline

1. Scanne `<sigmahq_dir>/regression_data` pour les fichiers `info.yml`
2. Pour chaque triplet : `rule.yml` + `.evtx` + `info.yml`
3. Parse le fichier EVTX → JSON imbriqué → format plat Winevt-compatible
4. Évalue l'événement contre la règle Sigma
5. Valide : la règle DOIT matcher (test de détection positive)
6. Rapport pass/fail par règle + résumé

### Sortie

```
  [1/100] proc_creation_win_bitsadmin_download ... [PASS] 1 match(es)
  [2/100] win_security_foo  ... [FAIL] FALSE NEGATIVE — no matches (EventID=4624, Channel=Security, provider=None)

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
cargo run --release --bin evtx_check ./sigma
```

---

## Comment ajouter un outil

1. Créer `src/bin/<name>.rs` avec un docstring en tête
2. Ajouter l'entrée dans `Cargo.toml` :

```toml
[[bin]]
name = "<name>"
path = "src/bin/<name>.rs"
```

3. Documenter ici avec usage et pipeline
