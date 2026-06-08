import os
import json

def load_centralized_analyzer_rules() -> dict:
    """
    Authoritative Rule Matrix Discovery Engine.
    Resolves configuration file scopes using structural module anchoring
    to eliminate environment path-drift failures across pip virtual env boundaries.
    """
    utils_dir = os.path.dirname(os.path.abspath(__file__))
    package_root = os.path.dirname(utils_dir)
    workspace_root = os.path.dirname(package_root)

    search_vectors = [
        os.path.join(package_root, "config", "analyzer_rules.json"),
        os.path.join(workspace_root, "config", "analyzer_rules.json"),
        os.path.abspath("config/analyzer_rules.json"),
        os.path.abspath("analyzer_rules.json")
    ]

    for path in search_vectors:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rules_matrix = json.load(f)
                # Normalize keys to guarantee fault-tolerant case-insensitive mappings
                return {str(k).strip().upper(): v for k, v in rules_matrix.items()}
            except Exception:
                pass

    return {}