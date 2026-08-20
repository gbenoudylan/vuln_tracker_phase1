# Vulnerability Prioritization & Remediation Tracker

Outil d'ingestion, priorisation et suivi de vulnérabilités, conçu pour absorber
des exports de scan à formats variables sans réécriture de code.

## Statut du projet

- [x] **Phase 1 — Ingestion universelle** (terminée, validée en conditions réelles)
- [x] **Phase 2 — Enrichissement CVSS via API NVD** (terminée, validée en conditions réelles)
- [x] **Phase 3 — Scoring composite + détection EOL** (terminée, validée en conditions réelles)
- [x] **Phase 4 — Dashboard Streamlit** (terminée)
- [ ] Phase 5 — Export du plan de remédiation

## Phase 4 : Dashboard Streamlit

### Ce que ça apporte

Une interface visuelle par-dessus le pipeline complet (Phases 1 à 3) : upload
d'un fichier, exécution automatique de l'ingestion + enrichissement CVSS +
enrichissement EPSS + scoring, puis visualisation interactive des résultats.

### Fonctionnalités

- **Upload de fichier** (CSV/Excel) depuis l'interface, ou utilisation d'un
  fichier d'exemple en un clic.
- **KPIs en un coup d'œil** : nombre total de vulnérabilités, nombre de P1,
  nombre d'équipements EOL concernés, score moyen de priorité.
- **Graphique de répartition** par niveau de priorité (P1 à P4).
- **Table filtrable** : par tier de priorité, ou équipements EOL uniquement,
  triée automatiquement par score de priorité décroissant.
- **Export CSV** du plan de remédiation filtré, prêt à diffuser.
- **Mise en cache** : un même fichier n'est jamais retraité deux fois (donc
  pas de nouveaux appels API inutiles au NVD/EPSS si tu recharges la page).

### Lancement

```bash
streamlit run dashboard/app.py
```

Une page s'ouvre automatiquement dans le navigateur (`http://localhost:8501`).

### Validation

Le lancement du serveur et la réponse HTTP ont été vérifiés en sandbox
(sans upload de fichier réel, faute d'interaction navigateur possible
dans cet environnement). **À toi de tester l'usage complet sur ton Mac** :
upload d'un fichier, filtres, export CSV.

## Phase 3 : Scoring composite + détection EOL

### Le problème résolu

Le CVSS seul est insuffisant pour prioriser : de nombreuses CVE au score CVSS
très élevé (9+) ne sont en réalité jamais exploitées, tandis que des CVE au
score plus modéré sur des actifs critiques exposés représentent un risque
réel immédiat. S'appuyer uniquement sur le CVSS conduit à noyer les vraies
urgences dans une longue liste de "critiques" théoriques.

### La méthodologie (alignée sur les pratiques du secteur)

Un score composite (0-100) combine 4 facteurs, à l'image des moteurs de
priorisation utilisés par les plateformes professionnelles (Tenable VPR,
Qualys QDS) :

| Facteur | Poids | Source |
|---|---|---|
| CVSS (sévérité technique) | 35% | Phase 2 (NVD) |
| EPSS (probabilité réelle d'exploitation sous 30 jours) | 30% | API FIRST.org (EPSS) |
| Criticité métier de l'actif | 25% | Colonne `environment` du fichier source |
| Statut EOL | 10% (bonus fixe +15 pts) | Colonne `is_eol` du fichier source |

Le résultat est classé en 4 tiers : **P1 - Critique**, **P2 - Élevée**,
**P3 - Moyenne**, **P4 - Faible**.

**Qu'est-ce que l'EPSS ?** Contrairement au CVSS (sévérité théorique), l'EPSS
donne la probabilité réelle qu'une CVE soit exploitée dans les 30 jours,
basée sur des données d'exploitation observées en conditions réelles
(scans, honeypots...). C'est ce qui permet de distinguer une CVE "critique
sur le papier" d'une CVE réellement dangereuse maintenant.

### Nouveaux modules

- `config/scoring_config.py` : tous les poids et barèmes, centralisés et
  ajustables sans toucher au code de calcul.
- `enrichment/epss_client.py` : client pour l'API EPSS (FIRST.org),
  même logique de cache et de tolérance aux pannes que le client NVD.
- `scoring/composite_score.py` : calcule le score final et le tier de
  priorité pour chaque ligne.

### Colonnes optionnelles à ajouter à vos exports

Pour un scoring fiable, ajoutez si possible ces deux colonnes à vos exports :
- `environment` (ou `criticite`, `environnement`...) : ex. `production-internet`,
  `production`, `test`
- `is_eol` (ou `eol`, `fin_de_vie`...) : `oui`/`non`

Si ces colonnes sont absentes, le module ne plante pas : il applique une
criticité par défaut neutre et considère qu'aucun équipement n'est EOL,
avec un message d'avertissement clair dans les logs.

### Utilisation

```bash
python -m scoring.composite_score data/export_format_A.csv
```

### Tests

Comme pour le NVD, le sandbox de développement n'a pas d'accès réseau à
l'API EPSS (`api.first.org`). Les tests simulent donc la logique de calcul :

```bash
python tests/test_scoring.py
```

**À valider sur ton poste avec accès internet réel** : la commande
d'utilisation ci-dessus, pour un appel EPSS réel.

## Phase 2 : Enrichissement CVSS via l'API NVD

### Le problème résolu

Les scores CVSS présents dans un export de scan datent du moment du scan.
Une CVE peut être réévaluée, republiée, ou son score CVSS ajusté après coup
par le NVD. S'appuyer uniquement sur le score du fichier source, c'est
risquer de prioriser une remédiation sur une donnée obsolète.

### La solution

- `enrichment/nvd_client.py` : client pour l'API publique du NVD
  (National Vulnerability Database), avec :
  - **Cache disque** (`data/cve_cache.json`) : chaque CVE n'est interrogée
    qu'une seule fois, les appels suivants sont instantanés et fonctionnent
    même hors-ligne une fois le cache rempli.
  - **Respect du rate-limit** : l'API publique sans clé est limitée à
    5 requêtes / 30s ; le client respecte un délai de sécurité entre
    chaque appel (accéléré automatiquement si une clé API est fournie).
  - **Tolérance aux pannes** : une erreur réseau ou une CVE introuvable
    n'interrompt jamais le traitement des autres CVE.
- `enrichment/cvss_enrichment.py` : applique le client à un DataFrame
  entier (sortie de la Phase 1), et calcule un score final avec repli
  automatique sur le score source si le NVD ne répond pas.

### Utilisation

```bash
python -m enrichment.cvss_enrichment data/export_format_A.csv
```

Optionnel : passer une clé API NVD (gratuite, augmente fortement la limite
de requêtes) via la variable d'environnement, ou directement en argument
de `NVDClient(api_key=...)`. Clé à demander sur
https://nvd.nist.gov/developers/request-an-api-key

### Tests

Le sandbox de développement n'a pas d'accès réseau au NVD. Les tests
simulent donc les réponses de l'API pour valider la logique de parsing,
le cache et le pipeline complet :

```bash
python tests/test_enrichment.py
```

**À faire sur ton poste avec accès internet réel** : lancer la commande
d'utilisation ci-dessus sur `data/export_format_A.csv` pour valider un
appel réel au NVD (les 2 CVE du fichier de test sont de vraies CVE connues :
CVE-2024-3400, CVE-2023-44487, CVE-2022-0778).

## Phase 1 : Ingestion universelle

### Le problème résolu

Les exports de scan de vulnérabilités changent de format selon la source, l'outil,
ou la personne qui les produit : noms de colonnes différents, ordre différent,
ligne d'en-tête pas toujours en première ligne, lignes de méta-données parasites.
Un script codé "en dur" sur un format casse à chaque changement.

### La solution

- `config/column_mapping.py` : dictionnaire central listant toutes les variantes
  connues pour chaque champ standard (ex. `hostname` peut être `Host`, `Device`,
  `Nom equipement`, etc.). **Pour supporter un nouveau format, on ajoute une ligne
  ici — on ne touche à aucun autre fichier.**
- `ingestion/ingest.py` :
  - Lit le fichier "à l'aveugle" (sans supposer où est l'en-tête)
  - Détecte automatiquement la ligne d'en-tête réelle
  - Gère les CSV mal formés (lignes de longueurs différentes)
  - Standardise les noms de colonnes vers les noms internes
  - Valide que les champs obligatoires sont bien présents, avec un message
    d'erreur explicite sinon

### Utilisation

```bash
pip install -r requirements.txt
python -m ingestion.ingest data/mon_export.csv
```

### Preuve de robustesse

Deux fichiers de test aux formats radicalement différents sont fournis dans `data/` :
- `export_format_A.csv` : en-tête ligne 0, colonnes anglaises
- `export_format_B.csv` : en-tête ligne 3, colonnes françaises réordonnées,
  lignes de méta-données parasites en tête de fichier

Les deux sont ingérés correctement par le même code, sans aucune modification.

## Structure du projet

```
vuln_tracker/
├── config/
│   └── column_mapping.py    # Référentiel des variantes de colonnes
├── ingestion/
│   └── ingest.py            # Module d'ingestion universelle
├── data/                    # Fichiers de test / exports réels
├── requirements.txt
└── README.md
```

## Stack technique

Python, pandas, rapidfuzz (matching approximatif), openpyxl (Excel),
API NVD (à venir en phase 2), Streamlit (à venir en phase 4).
