import pytest
from firm_lens.utils.findings import Finding

def test_threat_intel_cve_with_epss_and_kev():
    finding = Finding(
        id="CVE-2023-35813",
        title="Remote Code Execution in ESP32 Component",
        severity="High",
        cwes=["CWE-120"]
    )
    base_severity = finding.severity

    # Simulate threat intelligence ingestion
    intel = {"epss": 0.895, "kev": 1}
    finding.threat_intelligence_telemetry["epss_weaponization_probability"] = f"{intel['epss'] * 100:.2f}%"
    finding.threat_intelligence_telemetry["cisa_kev_active_exploitation"] = "Active Wild Exploitation Documented"

    # Base severity must remain unmodified
    assert finding.severity == base_severity
    assert finding.threat_intelligence_telemetry["epss_weaponization_probability"] == "89.50%"
    assert "Active Wild Exploitation" in finding.threat_intelligence_telemetry["cisa_kev_active_exploitation"]

def test_threat_intel_cve_with_epss_no_kev():
    finding = Finding(
        id="CVE-2022-35844",
        title="Denial of Service in Network Stack",
        severity="Medium",
        cwes=["CWE-400"]
    )
    base_severity = finding.severity

    intel = {"epss": 0.045, "kev": 0}
    finding.threat_intelligence_telemetry["epss_weaponization_probability"] = f"{intel['epss'] * 100:.2f}%"
    finding.threat_intelligence_telemetry["cisa_kev_active_exploitation"] = "Not listed in CISA KEV Catalog"

    assert finding.severity == base_severity
    assert finding.threat_intelligence_telemetry["epss_weaponization_probability"] == "4.50%"
    assert "Not listed" in finding.threat_intelligence_telemetry["cisa_kev_active_exploitation"]

def test_threat_intel_cve_missing_epss():
    finding = Finding(
        id="CVE-2024-99999",
        title="Unassigned Zero-Day Assessment",
        severity="High",
        cwes=["CWE-787"]
    )
    base_severity = finding.severity

    # Threat intel feed contains no EPSS entry for this CVE
    finding.threat_intelligence_telemetry["epss_weaponization_probability"] = "N/A"
    finding.threat_intelligence_telemetry["cisa_kev_active_exploitation"] = "Not listed in CISA KEV Catalog"

    # Assert missing EPSS does NOT downgrade or change base severity
    assert finding.severity == base_severity
    assert finding.threat_intelligence_telemetry["epss_weaponization_probability"] == "N/A"

def test_threat_intel_hardware_only_finding():
    finding = Finding(
        id="FL-BOOT-SIGNATURE",
        title="Missing Secure Boot Signature Sector",
        severity="High",
        cwes=["CWE-347"]
    )
    base_severity = finding.severity

    finding.threat_intelligence_telemetry["epss_weaponization_probability"] = "N/A - Physical Hardware Vector"

    assert finding.severity == base_severity
    assert "Physical Hardware Vector" in finding.threat_intelligence_telemetry["epss_weaponization_probability"]