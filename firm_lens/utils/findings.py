from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class Finding:
    """
    Industrial-grade finding container. 
    Uses dataclasses to reduce boilerplate and improve serialization.
    """
    id: str
    title: str
    description: str
    severity: str
    cwes: List[str]
    evidence: Optional[str] = ""
    offset: Optional[str] = "-"
    component: Optional[str] = "-"

    def to_dict(self):
        """Convert finding to a dictionary for JSON/HTML reporting."""
        return asdict(self)

    def detailed(self) -> str:
        """Provides the formatted string used for the 'Detailed Evidence' section."""
        cwe_str = ", ".join(self.cwes) if self.cwes else "-"
        return (
            f"ID: {self.id}\n"
            f"  • Title: {self.title}\n"
            f"  • Severity: {self.severity}\n"
            f"  • CWEs: {cwe_str}\n"
            f"  • Evidence: {self.evidence}\n"
            f"  • Offset: {self.offset}\n"
        )