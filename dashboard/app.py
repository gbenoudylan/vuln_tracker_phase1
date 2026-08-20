"""
Dashboard Streamlit — Vulnerability Prioritization & Remediation Tracker.

Interface interactive : upload d'un export de scan (n'importe quel format),
exécution du pipeline complet (ingestion -> CVSS -> EPSS -> scoring),
puis visualisation et filtrage des résultats.

Lancement :
    streamlit run dashboard/app.py
"""

from __future__ import annotations
import sys
import tempfile
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import streamlit as st

from ingestion.ingest import load_file, IngestionError
from enrichment.cvss_enrichment import enrich_dataframe
from scoring.composite_score import run_full_scoring_pipeline
from reporting.export import generate_excel_report, generate_pdf_report

st.set_page_config(
    page_title="Vulnerability Prioritization Tracker",
    page_icon="🛡️",
    layout="wide",
)

TIER_ORDER = ["P1 - Critique", "P2 - Élevée", "P3 - Moyenne", "P4 - Faible"]
TIER_COLORS = {
    "P1 - Critique": "#d62728",
    "P2 - Élevée": "#ff7f0e",
    "P3 - Moyenne": "#ffd700",
    "P4 - Faible": "#2ca02c",
}


@st.cache_data(show_spinner=False)
def run_pipeline(file_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    Exécute le pipeline complet sur un fichier uploadé.
    Mis en cache par contenu de fichier : un même fichier n'est jamais
    retraité deux fois (donc pas de ré-appel API inutile au NVD/EPSS).
    """
    suffix = Path(filename).suffix
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    df = load_file(tmp_path)
    df = enrich_dataframe(df)
    df = run_full_scoring_pipeline(df)
    return df


def main():
    st.title("🛡️ Vulnerability Prioritization & Remediation Tracker")
    st.caption(
        "Ingestion universelle · Enrichissement CVSS (NVD) · "
        "Probabilité d'exploitation (EPSS) · Score de priorité composite"
    )

    with st.sidebar:
        st.header("📁 Import")
        uploaded_file = st.file_uploader(
            "Export de scan (CSV ou Excel)",
            type=["csv", "xlsx", "xls"],
            help="N'importe quel format de colonnes est accepté — le mapping "
                 "s'adapte automatiquement.",
        )

        use_sample = False
        if uploaded_file is None:
            use_sample = st.checkbox("Utiliser un fichier d'exemple", value=True)

        st.divider()
        st.caption(
            "Les scores CVSS et EPSS sont récupérés en direct depuis le NVD "
            "et FIRST.org, puis mis en cache localement."
        )

    # --- Chargement des données ---
    df = None
    error = None

    try:
        if uploaded_file is not None:
            with st.spinner("Traitement du fichier (ingestion, enrichissement, scoring)..."):
                df = run_pipeline(uploaded_file.getvalue(), uploaded_file.name)
        elif use_sample:
            sample_path = Path(__file__).parent.parent / "data" / "export_format_A.csv"
            with st.spinner("Traitement du fichier d'exemple..."):
                df = run_pipeline(sample_path.read_bytes(), sample_path.name)
    except IngestionError as e:
        error = f"Erreur d'ingestion : {e}"
    except Exception as e:
        error = f"Erreur inattendue : {e}"

    if error:
        st.error(error)
        st.info(
            "Vérifiez que le fichier contient au minimum les colonnes "
            "correspondant à : nom d'équipement, identifiant CVE, score CVSS."
        )
        return

    if df is None:
        st.info("⬅️ Importez un fichier ou cochez 'Utiliser un fichier d'exemple' pour commencer.")
        return

    # --- KPIs ---
    st.subheader("Vue d'ensemble")
    col1, col2, col3, col4 = st.columns(4)

    total = len(df)
    n_p1 = (df["priority_tier"] == "P1 - Critique").sum()
    n_eol = df["is_eol_flagged"].sum() if "is_eol_flagged" in df.columns else 0
    avg_score = df["priority_score"].mean()

    col1.metric("Vulnérabilités totales", total)
    col2.metric("Priorité P1 - Critique", int(n_p1))
    col3.metric("Équipements EOL concernés", int(n_eol))
    col4.metric("Score moyen de priorité", f"{avg_score:.1f} / 100")

    st.divider()

    # --- Répartition par tier ---
    st.subheader("Répartition par niveau de priorité")
    tier_counts = df["priority_tier"].value_counts().reindex(TIER_ORDER, fill_value=0)
    st.bar_chart(tier_counts, color="#d62728")

    st.divider()

    # --- Filtres et table ---
    st.subheader("Détail des vulnérabilités")

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        selected_tiers = st.multiselect(
            "Filtrer par priorité", options=TIER_ORDER, default=TIER_ORDER
        )
    with filter_col2:
        show_eol_only = st.checkbox("Afficher uniquement les équipements EOL")

    filtered = df[df["priority_tier"].isin(selected_tiers)]
    if show_eol_only and "is_eol_flagged" in df.columns:
        filtered = filtered[filtered["is_eol_flagged"]]

    display_cols = [
        c for c in [
            "hostname", "cve_id", "vulnerability_name", "cvss_score_final",
            "epss_score", "environment", "is_eol_flagged",
            "priority_score", "priority_tier",
        ]
        if c in filtered.columns
    ]

    filtered_sorted = filtered[display_cols].sort_values("priority_score", ascending=False)

    st.dataframe(
        filtered_sorted,
        width="stretch",
        hide_index=True,
        column_config={
            "priority_score": st.column_config.ProgressColumn(
                "Score de priorité", min_value=0, max_value=100, format="%.1f"
            ),
            "epss_score": st.column_config.NumberColumn("EPSS", format="%.3f"),
            "cvss_score_final": st.column_config.NumberColumn("CVSS", format="%.1f"),
        },
    )

    st.download_button(
        "⬇️ Télécharger le plan priorisé (CSV)",
        data=filtered_sorted.to_csv(index=False).encode("utf-8"),
        file_name="plan_remediation_priorise.csv",
        mime="text/csv",
    )

    st.divider()

    # --- Rapports Excel / PDF ---
    st.subheader("📄 Rapports formatés")
    st.caption(
        "Génère un rapport mis en forme (mise en couleur par priorité, "
        "synthèse) à partir de la sélection filtrée ci-dessus."
    )

    report_col1, report_col2 = st.columns(2)

    with report_col1:
        if st.button("Générer le rapport Excel", use_container_width=True):
            with st.spinner("Génération du rapport Excel..."):
                excel_buffer = BytesIO()
                tmp_xlsx = Path(tempfile.gettempdir()) / "plan_remediation.xlsx"
                generate_excel_report(filtered, tmp_xlsx)
                excel_buffer.write(tmp_xlsx.read_bytes())
            st.download_button(
                "⬇️ Télécharger le rapport Excel",
                data=excel_buffer.getvalue(),
                file_name="plan_remediation.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )

    with report_col2:
        if st.button("Générer le rapport PDF", use_container_width=True):
            with st.spinner("Génération du rapport PDF..."):
                pdf_buffer = BytesIO()
                tmp_pdf = Path(tempfile.gettempdir()) / "plan_remediation.pdf"
                generate_pdf_report(filtered, tmp_pdf)
                pdf_buffer.write(tmp_pdf.read_bytes())
            st.download_button(
                "⬇️ Télécharger le rapport PDF",
                data=pdf_buffer.getvalue(),
                file_name="plan_remediation.pdf",
                mime="application/pdf",
                use_container_width=True,
            )


if __name__ == "__main__":
    main()
