"""
Configuration du scoring composite.

Centralise tous les poids et barèmes, pour pouvoir ajuster la méthodologie
de priorisation sans toucher au code de calcul.
"""

# Poids de chaque facteur dans le score final (doivent totaliser 1.0)
WEIGHTS = {
    "cvss": 0.35,
    "epss": 0.30,
    "criticality": 0.25,
    "eol": 0.10,
}

# Barème de criticité métier d'un actif, sur 100.
# Valeurs attendues dans la colonne 'environment' (insensible à la casse) :
CRITICALITY_SCALE = {
    "production-internet": 100,   # prod exposée sur internet : le pire cas
    "production-internet-facing": 100,
    "prod-internet": 100,
    "production": 75,             # prod interne, non exposée directement
    "prod": 75,
    "interne": 50,
    "internal": 50,
    "test": 20,
    "dev": 20,
    "recette": 20,
    "staging": 30,
}
DEFAULT_CRITICALITY = 50  # valeur appliquée si 'environment' est vide/inconnu

# Bonus appliqué (en points, sur le score final /100) si l'équipement est EOL.
# Un EOL ne recevra jamais de patch correctif -> le risque reste ouvert
# indéfiniment, ce qui justifie une pénalité fixe plutôt qu'une simple pondération.
EOL_BONUS_POINTS = 15

# Seuils de classification en tiers de priorité, sur le score final /100
PRIORITY_TIERS = [
    (85, "P1 - Critique"),
    (65, "P2 - Élevée"),
    (40, "P3 - Moyenne"),
    (0, "P4 - Faible"),
]


def classify_priority(score: float) -> str:
    """Retourne le libellé de tier de priorité correspondant à un score."""
    for threshold, label in PRIORITY_TIERS:
        if score >= threshold:
            return label
    return "P4 - Faible"


def get_criticality_score(environment_value) -> int:
    """Retourne le score de criticité (0-100) pour une valeur d'environnement donnée."""
    if environment_value is None or (isinstance(environment_value, float) and str(environment_value) == "nan"):
        return DEFAULT_CRITICALITY
    key = str(environment_value).strip().lower()
    return CRITICALITY_SCALE.get(key, DEFAULT_CRITICALITY)
