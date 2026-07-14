# Format de sortie

L'outil produit des données de régression compatibles avec le format du dépôt [SigmaHQ](https://github.com/SigmaHQ/sigma), prêtes pour la soumission de PR.

## Structure de répertoires

```
regression_data/
└── <rule_rel_path>/         # miroir du chemin de la règle sous sigma/rules/ (ou rules/<rule_id>)
    ├── info.yml
    ├── <rule_id>.json
    └── <rule_id>.evtx
```

Le répertoire miroir le chemin de la règle sous `rules/`. Par exemple :

```
sigma/rules/windows/builtin/security/win_security_foo.yml
    → regression_data/rules/windows/builtin/security/win_security_foo/
    → regression_data/rules/windows/builtin/security/win_security_foo/info.yml
    → regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.json
    → regression_data/rules/windows/builtin/security/win_security_foo/<rule_id>.evtx
```

## Contenu des fichiers

### `<rule_id>.json`

Un seul event, **JSON plat** avec des clés nommées selon Sigma (produit par `XmlParser`).
Les champs XML sont aplaties directement dans la forme plate que les règles Sigma attendent :

```json
{
  "EventID": "1",
  "SysmonEventID": "1",
  "ProcessId": "3904",
  "ThreadId": "4272",
  "Provider": "Microsoft-Windows-Sysmon",
  "_source": "etw",
  "Image": "C:\\Windows\\System32\\cmd.exe",
  "CommandLine": "C:\\WINDOWS\\system32\\cmd.exe /d /s /c \"whoami\"",
  "ParentImage": "C:\\Windows\\explorer.exe",
  "User": "SYSTEM"
}
```

### `info.yml`

```yaml
id: <uuid>                                    # UUID v4 unique par entrée info.yml
description: N/A
date: 2025-07-09
author: <rule_author_from_yaml>                # extrait du YAML de la règle
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

> `path` est le chemin relatif vers le fichier `.evtx` sous `regression_data/`.

Le YAML source de la règle est également annoté avec :

```yaml
regression_tests_path: regression_data/rules/<rule_rel_path>/info.yml
```

## Contraintes

- **Un event par règle** : chaque répertoire de régression contient exactement un event JSON.
  Seul le premier event correspondant est capturé.
- **EVTX binaire valide** : `<rule_id>.evtx` est écrit via `EvtExportLog` API (Windows) qui re-queries l'event par RecordID depuis le live log.
  Si `EvtExportLog` échoue (event purgé) ou sur non-Windows → fallback `.xml` (raw XML, pas de binaire invalide).
  Le `.json` compagnon porte les données réelles pour le matching Sigma.
