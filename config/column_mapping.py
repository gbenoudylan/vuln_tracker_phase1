"""
Configuration centrale du mapping de colonnes.

Chaque champ "standard" (utilisé partout dans le reste du code) est associé
à une liste de variantes possibles rencontrées dans les exports réels.

Pour ajouter la prise en charge d'un nouveau format : il suffit d'ajouter
la variante ici, sans toucher au reste du code (ingestion, scoring, dashboard).
"""

COLUMN_MAPPING = {
    "hostname": [
        "hostname", "host", "device", "device_name", "equipement",
        "équipement", "nom equipement", "nom_machine", "asset",
        "asset_name", "machine",
    ],
    "ip_address": [
        "ip", "ip_address", "adresse ip", "adresse_ip", "ip address",
    ],
    "cve_id": [
        "cve", "cve_id", "cve id", "vulnerability_id", "vuln_id",
        "identifiant cve", "id_vulnerabilite",
    ],
    "vulnerability_name": [
        "vulnerability", "vulnerability_name", "nom vulnerabilite",
        "titre", "title", "description courte", "vuln_name", "nom_vuln",
    ],
    "cvss_score": [
        "cvss", "cvss_score", "score cvss", "cvss score", "base_score",
        "score_base", "severity_score",
    ],
    "severity": [
        "severity", "severite", "sévérité", "criticite", "criticité",
        "risk_level", "niveau de risque",
    ],
    "detected_date": [
        "detected", "detected_date", "date_detection", "date detection",
        "first_seen", "date de decouverte", "scan_date",
    ],
    "status": [
        "status", "statut", "etat", "état", "remediation_status",
        "statut_remediation",
    ],
    "environment": [
        "environment", "environnement", "env", "criticite_metier",
        "business_criticality", "zone",
    ],
    "is_eol": [
        "eol", "end_of_life", "fin_de_vie", "is_eol", "obsolete",
    ],
}

# Champs obligatoires pour que le traitement puisse continuer.
# Si l'un d'eux est absent après mapping, on lève une erreur explicite
# plutôt que de planter plus loin silencieusement.
# Champs obligatoires pour que le traitement puisse continuer.
# Volontairement minimal : 'cvss_score' n'en fait PAS partie, car ce score
# est de toute façon récupéré via le NVD à l'enrichissement (Phase 2).
# Certaines sources légitimes (ex. le catalogue CISA KEV) ne fournissent
# d'ailleurs aucun score CVSS par nature : CISA liste des vulnérabilités
# activement exploitées, indépendamment de leur sévérité théorique.
REQUIRED_FIELDS = ["hostname", "cve_id"]
