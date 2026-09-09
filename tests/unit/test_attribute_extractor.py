"""Unit tests for Contextual Attribute Extractor across semi-structured telemetry."""
from __future__ import annotations

from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation, Provenance
from hunting.evidence.attribute_extractor import (
    extract_attributes_from_observation,
    extract_best_attribute,
)


def _make_obs(fields: dict, obs_id: str = "obs-001", query_id: str = "q-001") -> Observation:
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv2"}, scope_id="splunk_botsv2")
    return Observation(
        id=obs_id,
        cell_id="cell-1",
        query_id=query_id,
        timestamp="2017-08-24T04:20:44.000Z",
        provider_scope=scope,
        native_type="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        epistemic_type=EpistemicType.OBSERVED,
        fields=fields,
        provenance=Provenance(query_id=query_id, collector="splunk", ingest_time="2017-08-24T04:20:44.000Z"),
    )


class TestSoftwareVersionExtraction:
    def test_extract_version_from_installer_filename(self) -> None:
        """Verify extraction from Tor Browser installer filename in TargetFilename."""
        obs = _make_obs({
            "TargetFilename": r"C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe",
            "host": "wrk-aturing",
        })
        extracted = extract_attributes_from_observation(obs, "software_version", target_keyword="tor")
        assert len(extracted) >= 1
        assert extracted[0].value == "7.0.4"
        assert extracted[0].source_field == "TargetFilename"
        assert extracted[0].observation_id == "obs-001"

    def test_extract_version_from_image_path(self) -> None:
        """Verify extraction from application image path."""
        obs = _make_obs({
            "Image": r"C:\Program Files\SomeApp-v2.1.0\bin\app.exe",
            "host": "wrk-aturing",
        })
        extracted = extract_attributes_from_observation(obs, "software_version")
        assert len(extracted) >= 1
        assert extracted[0].value == "2.1.0"

    def test_extract_version_from_commandline(self) -> None:
        """Verify extraction from command line flag."""
        obs = _make_obs({
            "CommandLine": r'"C:\tools\agent.exe" --version 3.4.1 --daemon',
            "host": "server01",
        })
        extracted = extract_attributes_from_observation(obs, "software_version")
        assert any(e.value == "3.4.1" for e in extracted)

    def test_ignore_schema_version_numbers(self) -> None:
        """Ensure single integer schema versions like '4' from Sysmon are not extracted as software versions."""
        obs = _make_obs({
            "Version": "4",
            "host": "wrk-aturing",
        })
        extracted = extract_attributes_from_observation(obs, "software_version")
        # Single digit "4" is not valid semver
        assert not any(e.value == "4" for e in extracted)

    def test_extract_best_attribute_ranking(self) -> None:
        """Ensure specific installer version outranks generic firefox version for Tor Browser."""
        obs1 = _make_obs({
            "Image": r"C:\Users\amber.turing\Desktop\Tor Browser\Browser\firefox.exe",
            "ProductVersion": "52.4.0",
        }, obs_id="obs-firefox")
        obs2 = _make_obs({
            "TargetFilename": r"C:\Users\amber.turing\Downloads\torbrowser-install-7.0.4_en-US.exe",
        }, obs_id="obs-installer")

        best = extract_best_attribute([obs1, obs2], "software_version", target_keyword="tor")
        assert best is not None
        assert best.value == "7.0.4"
        assert best.observation_id == "obs-installer"


class TestHashExtraction:
    def test_extract_sha256(self) -> None:
        obs = _make_obs({
            "Hashes": "SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,MD5=d41d8cd98f00b204e9800998ecf8427e",
        })
        extracted = extract_attributes_from_observation(obs, "sha256")
        assert len(extracted) == 1
        assert extracted[0].value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
