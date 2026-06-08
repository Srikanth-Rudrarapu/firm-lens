import os
import ast

def get_all_python_files(root_dir):
    py_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.py') and file != 'audit_code.py':
                py_files.append(os.path.join(root, file))
    return py_files

def audit_project(root_dir):
    files = get_all_python_files(root_dir)
    defined_functions = {}
    called_functions = set()

    # Phase 1: Parse all files
    for filepath in files:
        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                tree = ast.parse(f.read(), filename=filepath)
                for node in ast.walk(tree):
                    # Track function definitions
                    if isinstance(node, ast.FunctionDef):
                        # Skip private/magic methods in classes
                        if not node.name.startswith('_'):
                            defined_functions[node.name] = filepath
                    # Track function calls
                    elif isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            called_functions.add(node.func.id)
                        elif isinstance(node.func, ast.Attribute):
                            called_functions.add(node.func.attr)
            except Exception as e:
                print(f"Error parsing {filepath}: {e}")

    # Phase 2: Identify unused functions
    unused = {name: path for name, path in defined_functions.items() if name not in called_functions}
    
    print("\n=== UNUSED / DEAD FUNCTIONS DETECTED ===")
    if not unused:
        print("No unused functions found! Codebase is lean.")
    for func, path in unused.items():
        print(f" Function: '{func}' in file: {path}")

if __name__ == "__main__":
    audit_project("Firmlens")