"""
Tests du module de scoring composite.

Comme pour le NVD, le sandbox de développement n'a pas accès au domaine
de l'API EPSS (api.first.org). On simule donc les réponses pour valider
la logique de calcul du score composite.

Sur ton poste avec accès internet réel, tout fonctionne sans modification :
python -m scoring.composite_score data/export_format_A.csv
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from config.scoring_config import get_criticality_score, classify_priority
from scoring.composite_score import compute_composite_score


def test_criticality_scale():
    assert get_criticality_score("Production-Internet") == 100
    assert get_criticality_score("Production") == 75
    assert get_criticality_score("Test") == 20
    assert get_criticality_score(None) == 50
    assert get_criticality_score("valeur_inconnue") == 50
    print("OK - test_criticality_scale")


def test_classify_priority():
    assert classify_priority(90) == "P1 - Critique"
    assert classify_priority(70) == "P2 - Élevée"
    assert classify_priority(45) == "P3 - Moyenne"
    assert classify_priority(10) == "P4 - Faible"
    print("OK - test_classify_priority")


def test_composite_score_worst_case():
    """
    Cas le plus critique possible : CVSS max, EPSS max, prod exposée, EOL.
    Doit produire un score très élevé (P1).
    """
    df = pd.DataFrame({
        "cve_id": ["CVE-TEST-0001"],
        "cvss_score_final": [10.0],
        "epss_score": [0.97],
        "environment": ["production-internet"],
        "is_eol": ["oui"],
    })
    result = compute_composite_score(df)
    score = result.loc[0, "priority_score"]
    tier = result.loc[0, "priority_tier"]

    assert score >= 95, f"Score attendu proche de 100, obtenu {score}"
    assert tier == "P1 - Critique"
    assert result.loc[0, "is_eol_flagged"] == True
    print(f"OK - test_composite_score_worst_case (score={score}, tier={tier})")


def test_composite_score_best_case():
    """
    Cas le plus bénin possible : CVSS faible, EPSS quasi nul, environnement
    de test, pas EOL. Doit produire un score faible (P4).
    """
    df = pd.DataFrame({
        "cve_id": ["CVE-TEST-0002"],
        "cvss_score_final": [2.0],
        "epss_score": [0.001],
        "environment": ["test"],
        "is_eol": ["non"],
    })
    result = compute_composite_score(df)
    score = result.loc[0, "priority_score"]
    tier = result.loc[0, "priority_tier"]

    assert score < 20, f"Score attendu faible, obtenu {score}"
    assert tier == "P4 - Faible"
    assert result.loc[0, "is_eol_flagged"] == False
    print(f"OK - test_composite_score_best_case (score={score}, tier={tier})")


def test_missing_optional_columns():
    """
    Si 'environment' et 'is_eol' sont absentes du fichier source (cas réel
    fréquent), le calcul ne doit pas planter : valeurs par défaut appliquées.
    """
    df = pd.DataFrame({
        "cve_id": ["CVE-TEST-0003"],
        "cvss_score_final": [7.0],
        "epss_score": [0.3],
    })
    result = compute_composite_score(df)
    assert "priority_score" in result.columns
    assert result.loc[0, "is_eol_flagged"] == False
    print("OK - test_missing_optional_columns (pas de plantage sans colonnes optionnelles)")


def test_eol_bonus_makes_a_difference():
    """Vérifie qu'un équipement EOL est bien pénalisé (score plus élevé) qu'un identique non-EOL."""
    base = {
        "cve_id": ["CVE-TEST-0004"],
        "cvss_score_final": [6.0],
        "epss_score": [0.1],
        "environment": ["production"],
    }
    df_eol = pd.DataFrame({**base, "is_eol": ["oui"]})
    df_no_eol = pd.DataFrame({**base, "is_eol": ["non"]})

    score_eol = compute_composite_score(df_eol).loc[0, "priority_score"]
    score_no_eol = compute_composite_score(df_no_eol).loc[0, "priority_score"]

    assert score_eol > score_no_eol, "Un équipement EOL doit avoir un score plus élevé"
    print(f"OK - test_eol_bonus_makes_a_difference (EOL={score_eol} > non-EOL={score_no_eol})")


if __name__ == "__main__":
    test_criticality_scale()
    test_classify_priority()
    test_composite_score_worst_case()
    test_composite_score_best_case()
    test_missing_optional_columns()
    test_eol_bonus_makes_a_difference()
    print("\nTous les tests sont passés.")
