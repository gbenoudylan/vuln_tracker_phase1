"""
Tests du module d'enrichissement CVSS.

Le sandbox de développement n'a pas accès au domaine du NVD
(services.nvd.nist.gov). On simule donc les réponses de l'API pour valider
la logique de parsing et d'enrichissement, indépendamment du réseau.

Sur ton poste MTN (avec accès internet normal), le module fonctionnera
en conditions réelles sans modification : lance simplement
`python -m enrichment.cvss_enrichment data/export_format_A.csv`
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
from enrichment.nvd_client import NVDClient

# Réponse NVD simulée, structure identique à une vraie réponse de l'API
MOCK_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-3400",
                "published": "2024-04-12T00:00:00.000",
                "descriptions": [
                    {"lang": "en", "value": "A command injection vulnerability..."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "baseScore": 10.0,
                            },
                            "baseSeverity": "CRITICAL",
                        }
                    ]
                },
            }
        }
    ]
}


def test_parse_response():
    """Vérifie que le parsing extrait correctement les bons champs."""
    result = NVDClient._parse_response("CVE-2024-3400", MOCK_NVD_RESPONSE)
    assert result["cvss_score_nvd"] == 10.0
    assert result["severity_nvd"] == "CRITICAL"
    assert result["published_date"] == "2024-04-12T00:00:00.000"
    print("OK - test_parse_response")


def test_parse_response_no_result():
    """Vérifie le comportement quand le NVD ne retourne aucune vulnérabilité."""
    result = NVDClient._parse_response("CVE-9999-9999", {"vulnerabilities": []})
    assert result is None
    print("OK - test_parse_response_no_result")


def test_client_uses_cache(tmp_cache_path):
    """
    Vérifie qu'un deuxième appel pour la même CVE ne déclenche pas
    une nouvelle requête réseau (utilisation du cache).
    """
    client = NVDClient(cache_path=tmp_cache_path)

    with patch("enrichment.nvd_client.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_NVD_RESPONSE
        mock_get.return_value = mock_resp

        # premier appel : doit taper l'API
        result1 = client.get_cve("CVE-2024-3400")
        assert mock_get.call_count == 1
        assert result1["cvss_score_nvd"] == 10.0

        # deuxième appel, même CVE : doit venir du cache, pas d'appel réseau
        result2 = client.get_cve("CVE-2024-3400")
        assert mock_get.call_count == 1  # inchangé
        assert result2 == result1

    print("OK - test_client_uses_cache")


def test_enrich_dataframe_end_to_end(tmp_cache_path):
    """
    Test de bout en bout : DataFrame standardisé -> enrichissement CVSS,
    avec l'appel réseau simulé.
    """
    from enrichment.cvss_enrichment import enrich_dataframe

    df = pd.DataFrame({
        "hostname": ["srv-web-01"],
        "cve_id": ["CVE-2024-3400"],
        "cvss_score": ["9.5"],  # score "source", légèrement différent du NVD
    })

    with patch("enrichment.nvd_client.requests.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_NVD_RESPONSE
        mock_get.return_value = mock_resp

        with patch("enrichment.nvd_client.NVDClient.__init__", autospec=True) as mock_init:
            def fake_init(self, api_key=None, cache_path=tmp_cache_path, timeout=15):
                self.api_key = api_key
                self.cache_path = tmp_cache_path
                self.timeout = timeout
                self._last_call_ts = 0.0
                self._cache = {}
            mock_init.side_effect = fake_init

            result = enrich_dataframe(df)

    assert result.loc[0, "cvss_score_nvd"] == 10.0
    assert result.loc[0, "cvss_score_final"] == 10.0  # priorité au NVD
    print("OK - test_enrich_dataframe_end_to_end")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_path = Path(tmp_dir) / "test_cache.json"

        test_parse_response()
        test_parse_response_no_result()
        test_client_uses_cache(cache_path)

        cache_path2 = Path(tmp_dir) / "test_cache2.json"
        test_enrich_dataframe_end_to_end(cache_path2)

    print("\nTous les tests sont passés.")
