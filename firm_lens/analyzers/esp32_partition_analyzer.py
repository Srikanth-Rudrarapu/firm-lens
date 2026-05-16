from typing import List, Dict, Any
from firm_lens.utils.findings import Finding

class ESP32PartitionAnalyzer:
    """
    Advanced Partition Table Security Analyzer.
    
    Identifies misconfigurations in device layout that could compromise 
    OTA updates, Secure Boot, or sensitive data storage in NVS.
    """

    def run(self, firmware_map: Dict[str, Any]) -> List[Finding]:
        """
        Consumes the structured firmware map from the Extractor.
        """
        findings: List[Finding] = []
        
        # Pull partitions directly from the pre-processed map
        partitions = firmware_map.get("partitions", [])

        if not partitions:
            findings.append(Finding(
                id="FIRM-ESP32-PART-001",
                title="No ESP32 partition table detected",
                description="The extractor could not find a valid partition table. This image may be a raw application binary lacking a table, or it may use a non-standard layout.",
                severity="Medium",
                cwes=["CWE-665"],
                evidence="partitions_list=empty",
                component="partition_table"
            ))
            return findings

        # Run specialized security checks
        findings.extend(self._analyze_core_partitions(partitions))
        findings.extend(self._analyze_nvs_security(partitions))
        findings.extend(self._analyze_ota_layout(partitions))
        findings.extend(self._analyze_custom_partitions(partitions))

        return findings

    def _analyze_core_partitions(self, partitions: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        labels = {p.get("name", "").lower() for p in partitions}
        apps = [p for p in partitions if p.get("type") == "app"]

        # Check for Hardware Secret Storage (NVS)
        if "nvs" not in labels:
            findings.append(Finding(
                id="FIRM-ESP32-PART-010",
                title="Missing NVS Partition",
                description="The Non-Volatile Storage (NVS) partition is missing. This is where ESP32 devices typically store Wi-Fi credentials and device-specific secrets.",
                severity="Medium",
                cwes=["CWE-665"],
                evidence=f"Found: {list(labels)}",
                component="partition_table"
            ))

        # Check for A/B Redundancy
        if len(apps) < 2:
            findings.append(Finding(
                id="FIRM-ESP32-PART-012",
                title="Lack of A/B OTA Redundancy",
                description="Only one application partition was found. Without a secondary slot, the device cannot perform safe 'bank-swapping' OTA updates, increasing the risk of bricking.",
                severity="Info",
                cwes=[],
                evidence=f"app_count={len(apps)}",
                component="partition_table"
            ))

        return findings

    def _analyze_nvs_security(self, partitions: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        for p in partitions:
            if p.get("name") == "nvs":
                size = p.get("size", 0)
                # O-1 Narrative: Heuristic analysis of secret storage capacity
                if size > 0x10000: # 64KB+
                    findings.append(Finding(
                        id="FIRM-ESP32-PART-021",
                        title="Large NVS partition detected",
                        description="A large NVS partition increases the attack surface for credential harvesting if flash encryption is disabled.",
                        severity="Medium",
                        cwes=["CWE-311"],
                        evidence=f"nvs_size={hex(size)}",
                        component="partition_table"
                    ))
        return findings

    def _analyze_ota_layout(self, partitions: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        labels = {p.get("name", "").lower() for p in partitions}
        
        if "otadata" not in labels:
            findings.append(Finding(
                id="FIRM-ESP32-PART-030",
                title="OTA Data partition missing",
                description="The 'otadata' partition is required for the bootloader to track which app slot is active. Its absence suggests a broken OTA implementation.",
                severity="High",
                cwes=["CWE-665"],
                evidence="otadata_missing",
                component="partition_table"
            ))
        return findings

    def _analyze_custom_partitions(self, partitions: List[Dict]) -> List[Finding]:
        findings: List[Finding] = []
        standard = {"nvs", "otadata", "phy_init", "factory", "app0", "app1", "ota_0", "ota_1"}
        
        for p in partitions:
            name = p.get("name", "")
            if name.lower() not in standard:
                findings.append(Finding(
                    id="FIRM-ESP32-PART-040",
                    title=f"Custom partition identified: '{name}'",
                    description="Non-standard partitions often contain proprietary logs, certificates, or unencrypted data specific to the manufacturer.",
                    severity="Medium",
                    cwes=["CWE-200"],
                    evidence=f"custom_label={name}",
                    component="partition_table"
                ))
        return findings