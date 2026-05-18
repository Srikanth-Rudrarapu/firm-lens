from typing import List

class Finding:
    """
    Standardized Security Finding Object Model.
    Unifies security telemetry across all distinct hardware and software analyzers
    to ensure seamless data rendering in JSON and HTML report engines.
    """
    def __init__(
        self,
        id: str,
        title: str,
        description: str,
        severity: str,  # Expected values: 'Critical', 'High', 'Medium', 'Low', 'Info'
        cwes: List[str],  # e.g., ['CWE-120', 'CWE-119']
        evidence: str,
        offset: str = "-",  # e.g., '0x13c54'
        component: str = "general"
    ):
        self.id = id
        self.title = title
        self.description = description
        self.severity = severity
        self.cwes = cwes if cwes else []
        self.evidence = evidence
        self.offset = offset
        self.component = component

    def to_dict(self) -> dict:
        """Converts findings seamlessly into structured maps for serialization engines."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cwes": self.cwes,
            "evidence": self.evidence,
            "offset": self.offset,
            "component": self.component
        }

    def detailed(self) -> str:
        """Provides the formatted string used for localized terminal/text outputs."""
        cwe_str = ", ".join(self.cwes) if self.cwes else "-"
        return (
            f"ID: {self.id}\n"
            f"  • Title: {self.title}\n"
            f"  • Severity: {self.severity}\n"
            f"  • CWEs: {cwe_str}\n"
            f"  • Evidence: {self.evidence}\n"
            f"  • Offset: {self.offset}\n"
            f"  • Component: {self.component}\n"
        )