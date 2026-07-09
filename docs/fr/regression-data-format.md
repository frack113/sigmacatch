# Format des données de régression Sigma

Format de données de régression pour les règles Sigma, compatible avec SigmaHQ.

## Objectif

Un jeu de régression se compose d'un **triplet** par règle : un fichier `info.yml` (métadonnées), un fichier `.json` (événement brut) et un fichier `.evtx` (template Windows Event Log). Ce triplet permet de valider qu'un moteur Sigma produit toujours les mêmes résultats pour une règle donnée face à un événement connu.

## Arborescence

```
regression_data/
├── rules/                            # Règles principales SigmaHQ
│   ├── cisco/
│   │   └── aaa/
│   │       └── cisco_cli_dot1x_disabled/
│   └── windows/
│       ├── builtin/
│       │   ├── security/             → <slug>/
│       │   ├── taskscheduler/        → <slug>/
│       │   └── wmi/                  → <slug>/
│       ├── file/
│       │   └── file_event/           → <slug>/
│       ├── image_load/               → <slug>/
│       ├── process_access/           → <slug>/
│       ├── process_creation/         → <slug>/
│       ├── registry/
│       │   ├── registry_delete/      → <slug>/
│       │   ├── registry_event/       → <slug>/
│       │   └── registry_set/         → <slug>/
│       └── sysmon/
│           └── sysmon_config_modification/ → <slug>/
├── rules-emerging-threats/           # Menaces émergentes
│   ├── 2025/
│   │   ├── Exploits/
│   │   │   └── CVE-2025-55182/      → <slug>/
│   │   └── Malware/
│   │       ├── Grixba/               → <slug>/
│   │       └── Shai-Hulud/           → <slug>/
│   └── 2026/
│       └── Exploits/
│           ├── CVE-2026-33829/       → <slug>/
│           └── RedSun/               → <slug>/
└── rules-threat-hunting/             # Chasse aux menaces
    └── windows/
        └── image_load/               → <slug>/
```

Les dossiers intermédiaires (`cisco/`, `windows/`, `builtin/`, etc.) reflètent la hiérarchie des catégories SigmaHQ. Le dernier dossier avant les fichiers est toujours un **slug** dérivé du nom de la règle YAML.

## Triplet de régression

Chaque règle avec régression contient un dossier (slug) avec exactement trois fichiers :

```
<slug>/
├── info.yml                    # Métadonnées + résultats du test
├── <rule_id>.json              # Événement brut (JSON plat)
└── <rule_id>.evtx              # EVTX valide via EvtWriteFile (XML Winevt)
```

Le `<rule_id>` est toujours l'**UUID** contenu dans `rule_metadata[0].id` du fichier `info.yml`. Il n'est jamais le nom du dossier.

Variant : certaines règles (ex: cisco) utilisent `.raw` au lieu de `.json` + `.evtx` quand le format EVTX n'est pas applicable.

## Schéma `info.yml`

### Champs requis

| Champ | Type | Description |
|-------|------|-------------|
| `id` | string (UUID) | Identifiant d'instance de test (distinct du rule_id de la règle) |
| `description` | string | Description du test (souvent `"N/A"`) |
| `date` | string (ISO 8601) | Date de création du test (`YYYY-MM-DD`) |
| `author` | string | Auteur du test |
| `rule_metadata` | sequence | Liste d'au moins un élément contenant les métadonnées de la règle |

### Champs optionnels

| Champ | Type | Description |
|-------|------|-------------|
| `regression_tests_info` | sequence | Détails des tests de régression |

### Structure `rule_metadata`

```yaml
rule_metadata:
  - id: <rule-UUID>           # Identifiant canonique de la règle SigmaHQ (UUID v4)
    title: <string>           # Titre de la règle
```

`rule_metadata[0].id` est l'**identifiant canonique**. C'est cet UUID qui identifie de manière unique la règle dans tout le système. Il est utilisé pour :
- Nommage des fichiers `.json` et `.evtx`
- Clé de lookup dans les moteurs Sigma
- Indexation dans les structures de données

### Structure `regression_tests_info` (optionnel)

```yaml
regression_tests_info:
  - name: Positive Detection Test
    type: evtx                  # ou "raw" pour certains formats
    provider: <ETW-provider>    # ex: Microsoft-Windows-Sysmon
    match_count: <int>          # Nombre de correspondances trouvées
    path: regression_data/.../<rule_id>.evtx  # Chemin relatif vers le template
```

### Exemple complet

```yaml
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
description: N/A
date: 2024-01-15
author: sigmacatch
rule_metadata:
  - id: d059842b-6b9d-4ed1-b5c3-5b89143c6ede
    title: Suspicious BitsAdmin Download
regression_tests_info:
  - name: Positive Detection Test
    type: evtx
    provider: Microsoft-Windows-Sysmon
    match_count: 1
    path: regression_data/rules/windows/process_creation/proc_creation_win_bitsadmin_download/d059842b-6b9d-4ed1-b5c3-5b89143c6ede.evtx
```

## Conventions de nommage

### Dossiers

- Le dernier dossier (slug) est dérivé du nom du fichier YAML source de la règle SigmaHQ
- Les dossiers intermédiaires reflètent la hiérarchie des catégories (`windows/process_creation/`, `cisco/aaa/`, etc.)
- Les slugs sont en minuscules avec des underscores (`proc_creation_win_bitsadmin_download`)
- **Le slug n'est jamais comparé au rule_id UUID**

### Fichiers de données

| Fichier | Format | Nom | Contenu |
|---------|--------|-----|---------|
| `info.yml` | YAML | Toujours `info.yml` | Métadonnées + résultats |
| `<rule_id>.json` | JSON | UUID v4 | Événement brut (JSON plat, clés Sigma) |
| `<rule_id>.evtx` | Binaire | UUID v4 | EVTX valide via EvtWriteFile (XML Winevt) |

Le `<rule_id>` dans les noms de fichiers est toujours le UUID de `rule_metadata[0].id`.

## Règles de validation

### Cohérence du rule_id

Le même UUID doit apparaître dans trois endroits :
1. `rule_metadata[0].id` dans `info.yml`
2. Nom du fichier `.json`
3. Nom du fichier `.evtx`

Si ces trois valeurs ne sont pas identiques, le triplet est incohérent.

### Complétude du triplet

Un triplet est **complet** si les trois fichiers existent dans le même dossier :
- `info.yml`
- `<rule_id>.json` (ou `<rule_id>.raw`)
- `<rule_id>.evtx`

Un triplet est **incomplet** si l'un des fichiers manque.

### Validation du format info.yml

Pour qu'un `info.yml` soit valide :
1. Le fichier doit être en UTF-8 (BOM autorisé)
2. Le champ `rule_metadata` doit être une séquence non vide
3. `rule_metadata[0].id` doit être un UUID v4 valide au format `8-4-4-4-12` (hexadécimal minuscule)
4. Le `id` au root du YAML (instance ID) est ignoré pour la validation du rule_id

### Validation du nommage

- Le nom du dossier parent n'est **jamais** validé contre le rule_id
- Les fichiers `.json`/`.evtx` doivent être nommés exactement `<rule_id>.<ext>`
- Les fichiers cachés (commençant par `.`) sont ignorés

## Plateformes

### Windows

La majorité des règles (process_creation, file_event, registry, etc.) ciblent Windows. Les événements `.json` contiennent des clés SigmaWindows spécifiques (`Image`, `CommandLine`, `ParentImage`, etc.).

### Cisco

Certaines règles réseau utilisent des formats natifs (`.raw` au lieu de `.json` + `.evtx`). Le champ `provider` dans `regression_tests_info` peut être absent.

### Emerging Threats

Règles spécifiques aux menaces émergentes, organisées par année et type (Exploits, Malware). Mêmes conventions de nommage que les règles principales.

### Threat Hunting

Règles de chasse aux menaces. Mêmes conventions de nommage.
