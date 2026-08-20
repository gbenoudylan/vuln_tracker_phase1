"""
Client pour l'API publique EPSS (Exploit Prediction Scoring System),
maintenue par FIRST.org : https://www.first.org/epss/

EPSS donne, pour chaque CVE, une probabilité (0 à 1) qu'elle soit
effectivement exploitée dans les 30 jours suivants, basée sur des données
réelles d'exploitation observées (scans, honeypots, dark web, etc.).

C'est la donnée qui permet de distinguer une CVE "critique sur le papier"
(CVSS élevé) d'une CVE "réellement dangereuse maintenant" (EPSS élevé).
Utilisée par la quasi-totalité des outils de vulnerability management
professionnels (Tenable, Qualys, Rapid7...) en complément du CVSS.

API gratuite, sans clé, sans rate-limit strict documenté (on garde
tout de même un cache et un léger throttle par prudence).
"""

from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("epss_client")

EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
DEFAULT_CACHE_PATH = Path(__file__).parent.parent / "data" / "epss_cache.json"
MIN_DELAY_BETWEEN_CALLS = 0.5  # secondes, throttle prudent


class EPSSClient:
    """Client avec cache pour l'API EPSS."""

    def __init__(self, cache_path: Path = DEFAULT_CACHE_PATH, timeout: int = 15):
        self.cache_path = cache_path
        self.timeout = timeout
        self._last_call_ts = 0.0
        self._cache = self._load_cache()

    def _load_cache(self) -> dict:
        if self.cache_path.exists():
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                logger.warning("Cache EPSS corrompu, redémarrage à vide.")
        return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=2, ensure_ascii=False)

    def get_epss(self, cve_id: str, force_refresh: bool = False) -> Optional[dict]:
        """
        Retourne {'epss': float 0-1, 'percentile': float 0-1} pour une CVE,
        ou None si indisponible.
        """
        cve_id = cve_id.strip().upper()

        if not force_refresh and cve_id in self._cache:
            return self._cache[cve_id]

        elapsed = time.time() - self._last_call_ts
        if elapsed < MIN_DELAY_BETWEEN_CALLS:
            time.sleep(MIN_DELAY_BETWEEN_CALLS - elapsed)

        try:
            resp = requests.get(
                EPSS_BASE_URL, params={"cve": cve_id}, timeout=self.timeout
            )
            self._last_call_ts = time.time()
            resp.raise_for_status()
            data = resp.json()

            results = data.get("data", [])
            if not results:
                logger.warning(f"{cve_id} : pas de score EPSS disponible.")
                self._cache[cve_id] = None
                self._save_cache()
                return None

            parsed = {
                "epss": float(results[0]["epss"]),
                "percentile": float(results[0]["percentile"]),
            }
            self._cache[cve_id] = parsed
            self._save_cache()
            return parsed

        except (requests.RequestException, KeyError, ValueError) as e:
            logger.error(f"{cve_id} : erreur EPSS ({e}). Ignorée pour cette exécution.")
            return None
