class HTMLReport:
    def __init__(self, findings):
        self.findings = findings

    def generate(self, output_path):
        html = "<html><body><h1>Firmware Analysis Report</h1>"
        for analyzer, items in self.findings.items():
            html += f"<h2>{analyzer}</h2><ul>"
            for f in items:
                html += f"<li><b>{f.title}</b>: {f.description}</li>"
            html += "</ul>"
        html += "</body></html>"

        with open(output_path, "w") as f:
            f.write(html)

        return output_path
