"""
Module d'enrichissement CVSS.

Prend en entrée le DataFrame standardisé produit par le module d'ingestion
(Phase 1), et vient compléter/rafraîchir les scores CVSS via l'API NVD
pour chaque CVE présente.

Logique de fallback : si le NVD ne répond pas pour une CVE (pas de réseau,
CVE introuvable, timeout), on garde le score CVSS déjà présent dans le
fichier source plutôt que de perdre l'information.
"""

from __future__ import annotations
import logging

import pandas as pd

from enrichment.nvd_client import NVDClient

logger = logging.getLogger("enrichment")


def enrich_dataframe(df: pd.DataFrame, api_key: str | None = None) -> pd.DataFrame:
    """
    Enrichit un DataFrame standardisé (colonne 'cve_id' obligatoire) avec
    les données CVSS à jour du NVD.

    Ajoute les colonnes :
        - cvss_score_nvd   : score CVSS officiel à jour (None si indisponible)
        - severity_nvd     : sévérité officielle (LOW/MEDIUM/HIGH/CRITICAL)
        - published_date   : date de publication officielle de la CVE
        - cvss_score_final : score retenu (NVD si disponible, sinon score source)
    """
    if "cve_id" not in df.columns:
        raise ValueError("Le DataFrame doit contenir une colonne 'cve_id'.")

    client = NVDClient(api_key=api_key)

    unique_cves = df["cve_id"].dropna().unique()
    logger.info(f"Enrichissement de {len(unique_cves)} CVE uniques via le NVD...")

    enrichment_results = {}
    for i, cve_id in enumerate(unique_cves, 1):
        logger.info(f"[{i}/{len(unique_cves)}] {cve_id}")
        result = client.get_cve(cve_id)
        enrichment_results[cve_id] = result

    df = df.copy()
    df["cvss_score_nvd"] = df["cve_id"].map(
        lambda c: enrichment_results.get(c, {}).get("cvss_score_nvd") if enrichment_results.get(c) else None
    )
    df["severity_nvd"] = df["cve_id"].map(
        lambda c: enrichment_results.get(c, {}).get("severity_nvd") if enrichment_results.get(c) else None
    )
    df["published_date"] = df["cve_id"].map(
        lambda c: enrichment_results.get(c, {}).get("published_date") if enrichment_results.get(c) else None
    )

    # Score final : priorité au NVD (à jour), repli sur le score source si absent
    source_score = df["cvss_score"] if "cvss_score" in df.columns else None
    df["cvss_score_final"] = df["cvss_score_nvd"]
    if source_score is not None:
        df["cvss_score_final"] = df["cvss_score_final"].fillna(
            pd.to_numeric(source_score, errors="coerce")
        )

    n_enriched = df["cvss_score_nvd"].notna().sum()
    logger.info(f"Enrichissement terminé : {n_enriched}/{len(df)} lignes enrichies via le NVD.")

    return df


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
    from ingestion.ingest import load_file

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    if len(sys.argv) < 2:
        print("Usage : python -m enrichment.cvss_enrichment <chemin_fichier>")
        sys.exit(1)

    df_ingested = load_file(sys.argv[1])
    df_enriched = enrich_dataframe(df_ingested)
    print(df_enriched[["cve_id", "cvss_score", "cvss_score_nvd", "severity_nvd", "cvss_score_final"]])
