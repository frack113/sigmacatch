# Format de sortie

L'outil produit des données de régression compatibles avec le format du dépôt
[SigmaHQ](https://github.com/SigmaHQ/sigma), prêtes pour la soumission de PR. Cette page
documente **ce que le pipeline écrit** ; le schéma complet (`info.yml`, conventions de
nommage, validation) est spécifié dans
[regression-data-format.md](regression-data-format.md).

## Structure de répertoires

La sortie vit toujours dans le repo sigma, sous `regression_data/` :

```text
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # miroir du chemin de la règle sous sigma/rules/
    ├── info.yml
    ├── <rule_id>.json       # optionnel (regression.add_json_output)
    └── <rule_id>.evtx       # ou <rule_id>.log côté Linux
```

Le répertoire miroir le chemin de la règle sous `rules/`. Par exemple :

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
```

## Ce que le pipeline écrit

| Fichier | Contenu | Condition |
|---|---|---|
| `info.yml` | Métadonnées du test (toujours écrit) | — |
| `<rule_id>.evtx` | EVTX binaire valide (Windows) | défaut |
| `<rule_id>.log` | Lignes originales (Linux) | défaut |
| `<rule_id>.json` | Événement brut sérialisé | `regression.add_json_output: true` |

### EVTX (Windows)

`<rule_id>.evtx` est produit par `EvtExportLog` (re-query de l'event par RecordID depuis le
log live, retries à backoff court) ou, pour les events sans record id, par le writer
EVTX pur Rust (`sigmacatch-evtx-writer`, déterministe, sans retry). Le fichier exporté est
**validé** (re-parse ≥ 1 record) ; un export vide/corrompu (événement purgé entre collecte
et export) est une erreur : le pipeline saute alors la règle ce cycle (pas de commit) et la
recapture plus tard.

### JSON auxiliaire

Le `.json` porte les données réelles pour le matching Sigma (`event_json_raw`). Sa forme
dépend du producteur : imbriquée et miroir fidèle du XML Winevt pour les events Windows,
plate (`{message, program, host, service}`) pour les events Linux. Voir
[regression-data-format.md](regression-data-format.md) pour les exemples.

## Annotation du YAML source

La règle Sigma source est également annotée avec :

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```
