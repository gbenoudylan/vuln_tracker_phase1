# Vulnerability Prioritization & Remediation Tracker

Outil d'ingestion, priorisation et suivi de vulnérabilités, conçu pour absorber
des exports de scan à formats variables sans réécriture de code.

## Statut du projet

- [x] **Phase 1 — Ingestion universelle** (terminée)
- [x] **Phase 2 — Enrichissement CVSS via API NVD** (terminée)
- [ ] Phase 3 — Scoring composite + détection EOL
- [ ] Phase 4 — Dashboard Streamlit
- [ ] Phase 5 — Export du plan de remédiation

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
