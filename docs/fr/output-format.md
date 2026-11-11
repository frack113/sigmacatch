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
    ├── <rule_id>.evtx       # Windows
    ├── <rule_id>.log        # Linux auditd/syslog/tail Sysmon
    └── <rule_id>.json       # données eBPF Linux, ou export brut optionnel
```

Le répertoire reflète le chemin de la règle sous `rules/`. Par exemple :

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
```

## Ce que le pipeline écrit

| Fichier | Contenu | Condition |
|---|---|---|
| `info.yml` | Métadonnées du test (toujours écrit) | — |
| `<rule_id>.evtx` | EVTX binaire valide (Windows) | collecteurs Windows |
| `<rule_id>.log` | Lignes originales (Linux auditd/syslog/tail Sysmon) | collecteurs lignes Linux |
| `<rule_id>.json` | Événement JSON/NDJSON (eBPF Linux), ou export brut optionnel | collecteur eBPF, ou `regression.add_json_output: true` (EVTX/log uniquement) |

### EVTX (Windows)

`<rule_id>.evtx` est produit par `EvtExportLog` (re-query de l'événement par RecordID depuis le
log live, retries à backoff court) ou, pour les événements sans record id, par le writer
EVTX pur Rust (module `evtx_writer` de `sigmacatch::regression`, déterministe, sans retry). Le fichier exporté est
**validé** (re-parse ≥ 1 record) ; un export vide/corrompu (événement purgé entre collecte
et export) est une erreur : le pipeline saute alors la règle ce cycle (pas de commit) et la
recapture plus tard.

### JSON / NDJSON eBPF (Linux)

Le collecteur eBPF écrit `<rule_id>.json` comme **fichier de données principal** :

- un événement → document JSON pretty-printé, `type: json` ;
- plusieurs enregistrements → NDJSON, un objet JSON compact par ligne, `type: ndjson`.

Les alertes auditd restent en `.log` (`type: log`) même lorsque eBPF est actif dans le même
binaire. Le `.json` porte la vue imbriquée `Event.System`/`Event.EventData` utilisée pour le
matching.

### JSON auxiliaire

Quand le fichier de données principal est `.evtx` ou `.log`,
`regression.add_json_output: true` ajoute un `.json` auxiliaire contenant l'événement brut.
Sa forme dépend du producteur : imbriquée et miroir fidèle du XML Winevt pour les événements
Windows, plate (`{message, program, host?}`, `host` optionnel) pour syslog et structurée
(`{stamp, type, node?, fields}`) pour auditd côté Linux. Un seul enregistrement est un
document JSON pretty-printé ; plusieurs enregistrements sont du NDJSON. Le validateur
(`regressiondata-check`) parse les deux formes en flux. Voir
[regression-data-format.md](regression-data-format.md) pour les exemples.

## Annotation du YAML source

La règle Sigma source est également annotée avec :

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```
