# Format de sortie

L'outil produit des données de régression compatibles avec le format du dépôt [SigmaHQ](https://github.com/SigmaHQ/sigma), prêtes pour la soumission de PR.

## Structure de répertoires

La sortie vit toujours dans le repo sigma, sous `regression_data/` :

```text
<sigma_repo_path>/regression_data/
└── <rule_rel_path>/         # miroir du chemin de la règle sous sigma/rules/
    ├── info.yml
    ├── <rule_id>.json
    └── <rule_id>.evtx
```

Le répertoire miroir le chemin de la règle sous `rules/`. Par exemple :

```text
sigma/rules/windows/builtin/security/win_security_foo.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/info.yml
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.json
    → sigma/regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.evtx
```

## Contenu des fichiers

### `<rule_id>.json`

Un seul event, sérialisé depuis `event_json_raw` — la forme JSON de l'event Winevt XML
produite par `sigmacatch-types` (roxmltree). Il est **imbriqué**, miroir fidèle de la structure
XML d'origine, et préserve les noms de clés `EventData` d'origine (espaces compris) :

```json
{
  "Event": {
    "#attributes": {
      "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    },
    "System": {
      "Provider": {
        "#attributes": {
          "Name": "Microsoft-Windows-Sysmon",
          "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
        }
      },
      "EventID": 1,
      "Version": 5,
      "Level": 4,
      "Task": 1,
      "Opcode": 0,
      "Keywords": "0x8000000000000000",
      "TimeCreated": {
        "#attributes": {
          "SystemTime": "2025-12-10T04:33:20.562782Z"
        }
      },
      "EventRecordID": 18463,
      "Correlation": null,
      "Execution": {
        "#attributes": {
          "ProcessID": 3208,
          "ThreadID": 1724
        }
      },
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "swachchhanda",
      "Security": {
        "#attributes": {
          "UserID": "S-1-5-18"
        }
      }
    },
    "EventData": {
      "RuleName": "-",
      "UtcTime": "2025-12-10 04:33:20.557",
      "ProcessGuid": "0197231E-F810-6938-B710-000000000800",
      "ProcessId": 7732,
      "Image": "C:\\Windows\\System32\\bitsadmin.exe",
      "CommandLine": "bitsadmin  /transfer n https://www.atomicredteam.io/atomic-red-team/atomics/T1218.011 hello.html",
      "User": "swachchhanda\\xodih",
      "Hashes": "MD5=4FCFE1D61E6D962F06CE2B61FC11BC0F,SHA256=6FEB16602A2FD1158C6F7E56E3B05A5E9AC01E88089535978C890EC6954A5AFA,IMPHASH=44794EEDDEB70144ABA2F1483E762F30"
    }
  }
}
```

Conventions notables :

- Les attributs XML sont stockés sous une clé `#attributes` (ex. `Provider`, `TimeCreated`).
- `EventData` conserve ses noms de clés **d'origine** — espaces compris (ex. `"RuleName"`, pas `Rule_Name`).
  `event_json` (la forme du moteur de détection) supprime ces espaces ; `event_json_raw` (ce fichier) non.
- Les valeurs numériques gardent leur type JSON natif (ex. `"EventID": 1`, pas `"1"`).

### `info.yml`

```yaml
id: <uuid>                                    # UUID v4 unique par entrée info.yml
description: N/A
date: 2025-12-10
author: <config.git.author>                   # depuis config.git.author (fallback : "Sigma Regression Generator")
rule_metadata:
    - id: <rule_id>
      title: <rule_title>
regression_tests_info:
    - name: Positive Detection Test
      type: evtx
      provider: Microsoft-Windows-Sysmon                # extrait dynamiquement du ProviderName de l'event
      match_count: 1                           # un event par entrée de test
      path: "regression_data/<rule_rel_path>/<rule_id>.evtx"  # chemin relatif vers le fichier EVTX
```

> `path` est le chemin relatif vers le fichier `.evtx` sous `regression_data/` (dans le repo sigma).

Le YAML source de la règle est également annoté avec :

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

### Logtype supportés

Le champ `type` de `regression_tests_info` (et la lecture des info.yml existants) reconnaît
4 types (`crates/sigmacatch-regression/src/logtype.rs`) : `evtx`, `json`, `raw`, `log`
— une valeur inconnue/absente retombe sur `json` avec un `warn!`. Le pipeline écrit
`.evtx` + `info.yml` (Windows) ou `.log` + `info.yml` (Linux) ; le `.json` auxiliaire
est ajouté seulement si `regression.add_json_output: true` (défaut : `false`). Un `.raw`
est possible pour des données non-Winevt
(ex. `regression_data/rules/cisco/aaa/cisco_cli_dot1x_disabled/ef0ff092-....raw`, `type: raw`,
généré hors pipeline — sa section `regression_tests_info` est commentée).
Pour les events `evtx` le provider doit être présent dans le XML de l'event (sinon la
génération échoue) ; pour les events `log` il provient du XML quand il existe
(Sysmon for Linux), avec repli sur `auditd` pour les events en texte brut.

**Exemple auditd (`type: log`, provider de repli `auditd` — event en texte brut sans XML) :**

```yaml
id: 60ff02c2-a649-436c-972d-7c6fe6af8711
description: N/A
date: 2026-08-20
author: frack113
rule_metadata:
  - id: 1543ae20-cbdf-4ec1-8d12-7664d667a825
    title: Suspicious Commands Linux
regression_tests_info:
  - name: Positive Detection Test
    type: log
    provider: auditd
    match_count: 1
    path: regression_data/rules/linux/auditd/execve/lnx_auditd_susp_cmds/1543ae20-cbdf-4ec1-8d12-7664d667a825.log
```

**Exemple Sysmon-for-Linux (`type: log`, provider extrait du XML de l'event) :**

```yaml
id: 8f2a5c31-9d64-4b7e-a1c2-3f5d8e90b7aa
description: N/A
date: 2026-08-23
author: frack113
rule_metadata:
  - id: f74107df-b6c6-4e80-bf00-4170b658162b
    title: Sudo Privilege Escalation CVE-2019-14287
regression_tests_info:
  - name: Positive Detection Test
    type: log
    provider: Linux-Sysmon
    match_count: 1
    path: regression_data/rules/linux/builtin/lnx_sudo_privilege_escalation_cve_2019_14287/f74107df-b6c6-4e80-bf00-4170b658162b.log
```

## Contraintes

- **Un event par règle** : chaque répertoire de régression contient exactement un event JSON.
  Seul le premier event correspondant est capturé.
- **EVTX binaire valide** : `<rule_id>.evtx` est produit par `EvtExportLog` (Windows — re-query
  de l'event par RecordID depuis le live log, retry à backoff court) ou, pour les events ETW /
  sans record id, par le writer EVTX pur Rust (`sigmacatch-evtx-writer`, déterministe, pas de
  retry). Le fichier exporté est **validé** (re-parse ≥ 1 record) ; un export vide/corrompu
  (événement purgé entre collecte et export) est une erreur : la règle est sautée ce cycle (pas de commit)
  et re-capturée plus tard.
  Le `.json` compagnon porte les données réelles pour le matching Sigma.
