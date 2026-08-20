"""
Client pour l'API publique du NVD (National Vulnerability Database).

Documentation officielle : https://nvd.nist.gov/developers/vulnerabilities

Points d'attention gérés ici :
- L'API publique sans clé est limitée à 5 requêtes / 30 secondes.
  On respecte donc un délai minimum entre deux appels.
- Chaque réponse est mise en cache localement (fichier JSON), pour ne
  jamais réinterroger deux fois la même CVE, et pour pouvoir retravailler
  hors-ligne une fois le cache rempli.
- Toute erreur réseau ou CVE introuvable est gérée proprement : on ne
  fait jamais planter tout le pipeline pour une seule CVE en échec.
"""

from __future__ import annotations
import json
import logging
import time
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("nvd_client")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Sans clé API : 5 requêtes / 30s -> on prend une marge de sécurité.
MIN_DELAY_BETWEEN_CALLS = 6.5  # secondes

DEFAULT_CACHE_PATH = Path(__file__).parent.parent / "data" / "cve_cache.json"


class NVDClient:
    """
    Petit client avec cache disque et respect du rate-limit NVD.

    Usage :
        client = NVDClient(api_key=None)  # api_key optionnelle mais recommandée
        data = client.get_cve("CVE-2024-3400")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        cache_path: Path = DEFAULT_CACHE_PATH,
        timeout: int = 15,
    ):
        self.api_key = api_key
        self.cache_path = cache_path
        self.timeout = timeout
        self._last_call_ts = 0.0
        self._cache = self._load_cache()

    # ---------- gestion du cache ----------

    def _load_cache(self) -> dict:
        if self.cache_path.exists():
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                logger.warning("Cache NVD corrompu, redémarrage à vide.")
        return {}

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=2, ensure_ascii=False)

    # ---------- appel API ----------

    def _respect_rate_limit(self) -> None:
        elapsed = time.time() - self._last_call_ts
        wait = MIN_DELAY_BETWEEN_CALLS - elapsed
        if self.api_key:
            wait = max(0.0, wait) * 0.1  # avec clé API, la limite est bien plus haute
        if wait > 0:
            time.sleep(wait)

    def get_cve(self, cve_id: str, force_refresh: bool = False) -> Optional[dict]:
        """
        Retourne les infos normalisées d'une CVE (score CVSS, sévérité,
        date de publication, description courte), ou None si introuvable
        ou en cas d'erreur réseau.
        """
        cve_id = cve_id.strip().upper()

        if not force_refresh and cve_id in self._cache:
            return self._cache[cve_id]

        self._respect_rate_limit()

        headers = {"apiKey": self.api_key} if self.api_key else {}
        params = {"cveId": cve_id}

        try:
            resp = requests.get(
                NVD_BASE_URL, params=params, headers=headers, timeout=self.timeout
            )
            self._last_call_ts = time.time()

            if resp.status_code == 404:
                logger.warning(f"{cve_id} : introuvable dans le NVD.")
                self._cache[cve_id] = None
                self._save_cache()
                return None

            resp.raise_for_status()
            data = resp.json()
            parsed = self._parse_response(cve_id, data)
            self._cache[cve_id] = parsed
            self._save_cache()
            return parsed

        except requests.RequestException as e:
            logger.error(f"{cve_id} : erreur réseau NVD ({e}). Ignorée pour cette exécution.")
            return None

    @staticmethod
    def _parse_response(cve_id: str, data: dict) -> Optional[dict]:
        """Extrait les champs utiles de la réponse brute de l'API NVD."""
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve = vulns[0]["cve"]

        # Le NVD peut retourner du CVSS v3.1, v3.0, ou v2 selon la CVE.
        # On prend le meilleur disponible, dans cet ordre de préférence.
        metrics = cve.get("metrics", {})
        cvss_score, cvss_version, severity = None, None, None

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_version = cvss_data.get("version")
                severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
                break

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        return {
            "cve_id": cve_id,
            "cvss_score_nvd": cvss_score,
            "cvss_version": cvss_version,
            "severity_nvd": severity,
            "published_date": cve.get("published"),
            "description": description,
        }
