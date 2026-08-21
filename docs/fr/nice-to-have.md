# Nice-to-have — Fonctionnalités à venir

Fonctionnalités identifiées comme utiles mais hors périmètre actuel. Pas de planning — documentées pour référence.

---

## 3. Support Linux

**État :** ✅ fait — collecteur `sigmacatch-auditd` opérationnel (tail `/var/log/audit/audit.log`, parsing `linux-audit-parser`, groupement par event id, logsource `product:linux, service:auditd, provider:auditd`). Données de régression `.log` + `.json` validées sur VM AlmaLinux avec Atomic RedTeam.

---

## 4. Support Correlation V2

**État :** le moteur `rsigma-eval` supporte les rules V2 (correlation), mais la pipeline ne les gère pas explicitement.

**Ce qui manque :**

- Les rules de corrélation (`correlation` type dans Sigma V2) nécessitent de garder en mémoire plusieurs events avant de décider
- La pipeline actuelle évalue chaque event individuellement — pas de buffer temporel
- Il faudrait un stateful evaluator qui accumule les events par `correlation_rule` et déclenche quand les conditions sont réunies
- Gestion des fenêtres temporelles (`timespan`) et des seuils (`field` count)

**Cas d'usage :** détection d'attaques multi-étapes, bruteforce, anomalies comportementales.
