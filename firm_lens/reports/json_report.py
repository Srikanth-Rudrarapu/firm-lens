import json
import os
from typing import List

from firm_lens.utils.findings import Finding


class JSONReport:
    """
    Save FirmLens findings to a JSON file.

    This format is ideal for:
      • CI/CD pipelines
      • Automated analysis
      • Dashboards
      • O-1 evidence (attach raw JSON output)
    """

    def __init__(self, indent: int = 2):
        self.indent = indent

    def save(self, findings: List[Finding], output_path: str) -> str:
        """
        Save findings to a JSON file.

        Args:
            findings: List of Finding objects
            output_path: Path chosen by the user

        Returns:
            The final written file path
        """

        # Ensure directory exists
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

        # Convert findings to serializable dicts
        data = [f.to_dict() for f in findings]

        report = {
            "firmware_analysis": data,
            "total_findings": len(data),
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=self.indent, ensure_ascii=False)

        return output_path
