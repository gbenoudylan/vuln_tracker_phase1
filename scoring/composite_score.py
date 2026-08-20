"""
Module de scoring composite.

Combine 4 signaux pour produire un score de priorité réaliste (0-100),
au lieu de se fier au seul CVSS :

    1. CVSS       -> sévérité technique brute
    2. EPSS       -> probabilité réelle d'exploitation (FIRST.org)
    3. Criticité  -> importance métier de l'actif touché
    4. EOL        -> pénalité si l'équipement ne recevra jamais de patch

C'est la même logique que les outils professionnels de type Tenable VPR
ou Qualys QDS : le CVSS seul sur-priorise trop de vulnérabilités qui ne
seront jamais exploitées en pratique.
"""

from __future__ import annotations
import logging

import pandas as pd

from config.scoring_config import (
    WEIGHTS,
    EOL_BONUS_POINTS,
    classify_priority,
    get_criticality_score,
)
from enrichment.epss_client import EPSSClient

logger = logging.getLogger("scoring")


def _parse_bool(value) -> bool:
    """Interprète largement les valeurs de la colonne is_eol (oui/yes/true/1...)."""
    if value is None:
        return False
    return str(value).strip().lower() in {"oui", "yes", "true", "1", "vrai", "y"}


def add_epss_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Enrichit le DataFrame avec le score EPSS de chaque CVE."""
    if "cve_id" not in df.columns:
        raise ValueError("Le DataFrame doit contenir une colonne 'cve_id'.")

    client = EPSSClient()
    unique_cves = df["cve_id"].dropna().unique()
    logger.info(f"Récupération EPSS pour {len(unique_cves)} CVE uniques...")

    results = {}
    for i, cve_id in enumerate(unique_cves, 1):
        logger.info(f"[{i}/{len(unique_cves)}] {cve_id}")
        results[cve_id] = client.get_epss(cve_id)

    df = df.copy()
    df["epss_score"] = df["cve_id"].map(
        lambda c: results.get(c, {}).get("epss") if results.get(c) else None
    )
    df["epss_percentile"] = df["cve_id"].map(
        lambda c: results.get(c, {}).get("percentile") if results.get(c) else None
    )
    return df


def compute_composite_score(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calcule le score composite final (0-100) et le tier de priorité.

    Prérequis colonnes : 'cvss_score_final' (Phase 2), 'epss_score'
    (produit par add_epss_scores), 'environment' et 'is_eol' (optionnelles,
    valeurs par défaut appliquées si absentes).
    """
    df = df.copy()

    # --- Normalisation de chaque facteur sur une échelle 0-100 ---

    cvss_col = "cvss_score_final" if "cvss_score_final" in df.columns else "cvss_score"
    cvss_norm = pd.to_numeric(df[cvss_col], errors="coerce").fillna(0) * 10  # 0-10 -> 0-100

    epss_norm = pd.to_numeric(df.get("epss_score"), errors="coerce").fillna(0) * 100  # 0-1 -> 0-100

    if "environment" in df.columns:
        criticality_norm = df["environment"].apply(get_criticality_score)
    else:
        logger.warning(
            "Colonne 'environment' absente : criticité par défaut appliquée à tout le fichier. "
            "Ajoutez cette colonne à votre export pour un score fiable."
        )
        criticality_norm = pd.Series([get_criticality_score(None)] * len(df))

    if "is_eol" in df.columns:
        is_eol = df["is_eol"].apply(_parse_bool)
    else:
        is_eol = pd.Series([False] * len(df))

    # --- Score pondéré ---

    base_score = (
        cvss_norm * WEIGHTS["cvss"]
        + epss_norm * WEIGHTS["epss"]
        + criticality_norm * WEIGHTS["criticality"]
    )
    # Le poids "eol" de la config sert de référence documentaire ; le bonus
    # est appliqué en points fixes pour rester lisible et non dilué par la moyenne.
    eol_bonus = is_eol.apply(lambda x: EOL_BONUS_POINTS if x else 0)

    final_score = (base_score + eol_bonus).clip(upper=100).round(1)

    df["priority_score"] = final_score
    df["priority_tier"] = final_score.apply(classify_priority)
    df["is_eol_flagged"] = is_eol

    logger.info(
        f"Scoring terminé. Répartition des priorités :\n"
        f"{df['priority_tier'].value_counts().sort_index().to_string()}"
    )

    return df


def run_full_scoring_pipeline(df: pd.DataFrame) -> pd.DataFrame:
    """Enchaîne l'enrichissement EPSS puis le calcul du score composite."""
    df = add_epss_scores(df)
    df = compute_composite_score(df)
    return df


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    from ingestion.ingest import load_file
    from enrichment.cvss_enrichment import enrich_dataframe

    if len(sys.argv) < 2:
        print("Usage : python -m scoring.composite_score <chemin_fichier>")
        sys.exit(1)

    df_ingested = load_file(sys.argv[1])
    df_enriched = enrich_dataframe(df_ingested)
    df_scored = run_full_scoring_pipeline(df_enriched)

    cols_to_show = [
        "hostname", "cve_id", "cvss_score_final", "epss_score",
        "priority_score", "priority_tier", "is_eol_flagged",
    ]
    cols_to_show = [c for c in cols_to_show if c in df_scored.columns]
    print(df_scored[cols_to_show].sort_values("priority_score", ascending=False))
