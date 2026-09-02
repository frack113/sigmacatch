# Format des données de régression Sigma

Format de données de régression pour les règles Sigma, compatible avec SigmaHQ.

## Objectif

Un jeu de régression se compose par règle d'un fichier `info.yml` (métadonnées) et d'un **fichier de données** (`<rule_id>.evtx` pour Windows, `<rule_id>.log` pour Linux). Un `.json` auxiliaire (événement brut) peut s'y ajouter via l'option `regression.add_json_output` (défaut : `false`). Cet ensemble permet de valider qu'un moteur Sigma produit toujours les mêmes résultats pour une règle donnée face à un événement connu.

## Arborescence

La sortie miroir la hiérarchie SigmaHQ sous `rules/`, `rules-emerging-threats/` et
`rules-threat-hunting/` :

```text
regression_data/
├── rules/windows/process_creation/<slug>/            # règles principales
├── rules/linux/auditd/execve/<slug>/
└── rules-emerging-threats/2026/Exploits/CVE-2026-33829/<slug>/
```

Les dossiers intermédiaires reflètent la hiérarchie des catégories SigmaHQ. Le dernier
dossier avant les fichiers est toujours un **slug** dérivé du nom de la règle YAML.

## Contenu d'un dossier de régression

Chaque règle avec régression contient un dossier (slug) avec :

```text
<slug>/
├── info.yml                    # Métadonnées + résultats du test
├── <rule_id>.evtx              # EVTX valide (EvtExportLog ou writer pur Rust)
└── <rule_id>.json              # Optionnel (regression.add_json_output) — événement brut
```

Le `<rule_id>` est toujours l'**UUID** contenu dans `rule_metadata[0].id` du fichier `info.yml`. Il n'est jamais le nom du dossier.

Variantes : certaines règles (ex. cisco) utilisent `.raw` quand le format EVTX n'est pas applicable. Les règles Linux utilisent `.log` (lignes originales complètes : auditd, syslog ou XML Sysmon-for-Linux). Le fichier de données + `info.yml` constituent la sortie obligatoire ; le `.json` est un supplément optionnel.

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

- Nommage des fichiers de données (`.evtx`, `.log`, `.json`)
- Clé de lookup dans les moteurs Sigma
- Indexation dans les structures de données

### Structure `regression_tests_info` (optionnel)

```yaml
regression_tests_info:
  - name: Positive Detection Test
    type: evtx                  # ou "raw" pour cisco, "log" pour Linux (auditd/syslog/sysmon)
    provider: <ProviderName>    # extrait dynamiquement du ProviderName XML (ex: Microsoft-Windows-Sysmon, ou "auditd")
    match_count: <int>          # Nombre de correspondances trouvées
    path: regression_data/.../<rule_id>.evtx  # Chemin relatif vers le fichier de données
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

### Exemples `.log` (Linux)

**auditd (`type: log`, provider de repli `auditd` — event en texte brut sans XML) :**

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

**Sysmon-for-Linux (`type: log`, provider extrait du XML de l'event) :**

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
| `<rule_id>.evtx` | Binaire | UUID v4 | EVTX valide (EvtExportLog ou writer pur Rust ; validé ≥ 1 record à l'écriture) |
| `<rule_id>.log` | Texte | UUID v4 | Événement complet (lignes auditd originales multi-records, lignes syslog, ou XML Sysmon-for-Linux) |
| `<rule_id>.json` | JSON | UUID v4 | Optionnel (`regression.add_json_output`) — événement brut (JSON imbriqué Winevt ou JSON plat Linux) |

Le `<rule_id>` dans les noms de fichiers est toujours l'UUID de `rule_metadata[0].id`.

## Règles de validation

### Cohérence du rule_id

Le même UUID doit apparaître dans `rule_metadata[0].id` de `info.yml` et dans le nom de chaque fichier de données présent. Si ces valeurs divergent, le jeu est incohérent.

### Complétude

Un jeu est **complet** si :

- `info.yml` existe
- le fichier de données référencé par `regression_tests_info[0].path` existe et est valide (magic EVTX / texte non-vide, taille ≤ 64 MiB)

Le `.json` auxiliaire n'entre pas en ligne de compte dans la validité.

### Validation du format info.yml

Pour qu'un `info.yml` soit valide :

1. Le fichier doit être en UTF-8 (BOM autorisé)
2. Le champ `rule_metadata` doit être une séquence non vide
3. `rule_metadata[0].id` doit être un UUID parseable ; une erreur dure est levée uniquement sur les valeurs non parseables. Les ids non v4 ou non canoniques minuscules (`8-4-4-4-12`) sont acceptés avec un avertissement — l'amont SigmaHQ en publie et leurs entrées de régression ne doivent pas être abandonnées
4. Le `id` au root du YAML (instance ID) est ignoré pour la validation du rule_id

### Validation du nommage

- Le nom du dossier parent n'est **jamais** validé contre le rule_id
- Les fichiers de données doivent être nommés exactement `<rule_id>.<ext>`
- Les fichiers cachés (commençant par `.`) sont ignorés

## Plateformes

### Windows

La majorité des règles (process_creation, file_event, registry, etc.) ciblent Windows. Les événements `.json` contiennent des clés propres aux événements Windows (`Image`, `CommandLine`, `ParentImage`, etc.).

### Cisco

Certaines règles réseau utilisent des formats natifs (`.raw` au lieu de `.json` + `.evtx`). Le champ `provider` dans `regression_tests_info` peut être absent.

### Linux (auditd / syslog / sysmon)

Trois collecteurs tournent en parallèle, chacun gardé par sa source — la spécification
complète (fichiers tailés, gardes, parsing) vit dans [architecture.md](architecture.md).
Toutes leurs données de régression utilisent `.log` (lignes originales complètes : records
auditd groupés par `timestamp:sequence`, lignes syslog RFC3164, ou XML Sysmon-for-Linux).

Sur les hôtes qui transfèrent les records audit vers syslog (audisp/rsyslog), les deux
pipelines capturent la même activité : une règle basée sur auditd et une règle basée sur
syslog peuvent toutes deux produire des données de régression à partir d'elle. Le provider
écrit dans `info.yml` provient du XML de l'event quand il existe (`Linux-Sysmon` pour les
événements Sysmon-for-Linux), avec repli sur `auditd` pour les événements en texte brut.

### Emerging Threats

Règles spécifiques aux menaces émergentes, organisées par année et type (Exploits, Malware). Mêmes conventions de nommage que les règles principales.

### Threat Hunting

Règles de chasse aux menaces. Mêmes conventions de nommage.
