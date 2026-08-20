"""
Module d'ingestion universelle.

Objectif : lire un export de scan de vulnérabilités (CSV ou Excel), quel
que soit son format exact (noms de colonnes, ordre, position de l'en-tête,
feuille utilisée), et retourner un DataFrame avec des noms de colonnes
standardisés, prêts à être utilisés par les modules suivants (scoring,
dashboard...).

Aucune logique métier ici : ce module ne fait QUE de la normalisation
structurelle. C'est ce découplage qui permet d'absorber un changement de
format sans toucher au reste du pipeline.
"""

from __future__ import annotations
import logging
from pathlib import Path

import pandas as pd

try:
    from rapidfuzz import fuzz
    _HAS_RAPIDFUZZ = True
except ImportError:
    _HAS_RAPIDFUZZ = False

from config.column_mapping import COLUMN_MAPPING, REQUIRED_FIELDS

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger("ingestion")


class IngestionError(Exception):
    """Erreur levée quand un fichier ne peut pas être exploité de façon fiable."""


def _normalize(text: str) -> str:
    """Nettoie une chaîne pour la comparaison : minuscule, espaces normalisés."""
    return str(text).strip().lower().replace("_", " ").replace("-", " ")


def _score_header_row(row: pd.Series) -> int:
    """
    Compte combien de cellules d'une ligne correspondent à une variante
    connue du mapping. Sert à détecter automatiquement où se trouve la
    vraie ligne d'en-tête dans un fichier (elle n'est pas toujours en ligne 0).
    """
    all_variants = {
        _normalize(v) for variants in COLUMN_MAPPING.values() for v in variants
    }
    score = 0
    for cell in row:
        if pd.isna(cell):
            continue
        cell_norm = _normalize(cell)
        if cell_norm in all_variants:
            score += 1
    return score


def _detect_header_row(raw: pd.DataFrame, max_scan_rows: int = 15) -> int:
    """
    Scanne les N premières lignes d'un DataFrame lu sans en-tête et retourne
    l'index de la ligne la plus probable pour être l'en-tête réel.
    """
    best_row, best_score = 0, -1
    for i in range(min(max_scan_rows, len(raw))):
        score = _score_header_row(raw.iloc[i])
        if score > best_score:
            best_row, best_score = i, score
    if best_score <= 0:
        logger.warning(
            "Aucune ligne d'en-tête reconnue avec certitude, "
            "utilisation de la ligne 0 par défaut."
        )
        return 0
    logger.info(f"En-tête détecté à la ligne {best_row} (score={best_score}).")
    return best_row


def _match_column(col_name: str, threshold: int = 85) -> str | None:
    """
    Tente de faire correspondre un nom de colonne brut à un champ standard.
    1) correspondance exacte (normalisée) contre le mapping
    2) sinon, fuzzy matching si rapidfuzz est disponible
    """
    col_norm = _normalize(col_name)

    for standard_name, variants in COLUMN_MAPPING.items():
        if col_norm in [_normalize(v) for v in variants]:
            return standard_name

    if _HAS_RAPIDFUZZ:
        best_field, best_score = None, 0
        for standard_name, variants in COLUMN_MAPPING.items():
            for v in variants:
                s = fuzz.ratio(col_norm, _normalize(v))
                if s > best_score:
                    best_field, best_score = standard_name, s
        if best_score >= threshold:
            logger.info(
                f"Colonne '{col_name}' -> '{best_field}' "
                f"(fuzzy match, score={best_score})."
            )
            return best_field

    return None


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Renomme les colonnes du DataFrame vers les noms standards internes."""
    rename_map = {}
    unmatched = []

    for col in df.columns:
        matched = _match_column(col)
        if matched:
            rename_map[col] = matched
        else:
            unmatched.append(col)

    if unmatched:
        logger.info(f"Colonnes non reconnues (ignorées) : {unmatched}")

    return df.rename(columns=rename_map)


def validate_required_fields(df: pd.DataFrame) -> None:
    """Vérifie que les champs indispensables sont présents après mapping."""
    missing = [f for f in REQUIRED_FIELDS if f not in df.columns]
    if missing:
        raise IngestionError(
            f"Champs obligatoires manquants après mapping : {missing}. "
            f"Colonnes disponibles : {list(df.columns)}. "
            f"-> Ajoutez la variante manquante dans config/column_mapping.py"
        )


def _read_ragged_csv(path: Path) -> pd.DataFrame:
    """
    Lit un CSV "sale" : lignes de longueurs différentes (méta-données,
    titres de rapport, lignes vides avant le vrai en-tête). pandas.read_csv
    échoue sur ces fichiers ; on lit donc ligne par ligne et on complète
    les lignes trop courtes, plutôt que de planter.
    """
    import csv

    with open(path, newline="", encoding="utf-8-sig") as f:
        # sniff pour détecter le séparateur (, ou ;)
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel  # défaut : virgule
        rows = list(csv.reader(f, dialect))

    max_cols = max(len(r) for r in rows) if rows else 0
    rows = [r + [None] * (max_cols - len(r)) for r in rows]
    return pd.DataFrame(rows)


def load_file(path: str | Path) -> pd.DataFrame:
    """
    Point d'entrée principal du module.

    Lit un fichier CSV ou Excel, détecte automatiquement la ligne d'en-tête,
    standardise les noms de colonnes, et valide la présence des champs
    obligatoires.

    Retourne un DataFrame propre, prêt pour le module de scoring.
    """
    path = Path(path)
    if not path.exists():
        raise IngestionError(f"Fichier introuvable : {path}")

    logger.info(f"Lecture du fichier : {path.name}")

    if path.suffix.lower() in [".xlsx", ".xls"]:
        raw = pd.read_excel(path, header=None, sheet_name=0)
    elif path.suffix.lower() == ".csv":
        raw = _read_ragged_csv(path)
    else:
        raise IngestionError(f"Format de fichier non supporté : {path.suffix}")

    header_row_idx = _detect_header_row(raw)
    df = raw.iloc[header_row_idx + 1:].copy()
    df.columns = raw.iloc[header_row_idx]
    df = df.dropna(how="all").reset_index(drop=True)

    df = standardize_columns(df)
    validate_required_fields(df)

    logger.info(f"Ingestion réussie : {len(df)} lignes, colonnes finales : {list(df.columns)}")
    return df


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage : python ingest.py <chemin_fichier>")
        sys.exit(1)

    result_df = load_file(sys.argv[1])
    print(result_df.head())
