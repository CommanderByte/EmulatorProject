# Improved version of initGen.py

import os
import ast
from pathlib import Path
from collections import defaultdict

def autopopulate_init(package_dir: str):
    """
    Walk through each subpackage in `package_dir`. For each directory:
      - Ensure __init__.py exists.
      - If it has .py files: import * from them and declare __all__.
      - If it has subdirs: import those submodules and add them to __all__.

    Also prints circular import warnings.
    """
    package_dir = Path(package_dir).resolve()
    import_graph = defaultdict(set)

    for dirpath, dirnames, filenames in os.walk(package_dir):
        dir_path = Path(dirpath)

        # Skip __pycache__ and hidden/system dirs
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d != '__pycache__']

        py_files = [f for f in filenames if f.endswith('.py') and f != '__init__.py']
        submodules = dirnames[:]

        # Ensure __init__.py exists
        init_path = dir_path / '__init__.py'
        if not init_path.exists():
            init_path.touch()
            print(f"Created empty: {init_path}")

        # If no py files or submodules, skip writing content
        if not py_files and not submodules:
            continue

        imports = []
        all_symbols = []

        for py_file in sorted(py_files):
            mod = py_file[:-3]
            imports.append(f"from .{mod} import *")
            all_symbols.append(f"    '{mod}',")

            # Track imports for circular check
            try:
                with open(dir_path / py_file, "r", encoding="utf-8") as src_file:
                    tree = ast.parse(src_file.read())
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ImportFrom) and node.module:
                            if node.level == 1:
                                import_graph[mod].add(node.module.split('.')[0])
            except Exception as e:
                print(f"[ERROR] Could not parse {py_file}: {e}")

        # Add submodules
        for sub in sorted(submodules):
            imports.append(f"from . import {sub}")
            all_symbols.append(f"    '{sub}',")

        init_code = (
            '\n'.join(imports) +
            '\n\n__all__ = [\n' +
            '\n'.join(all_symbols) +
            '\n]\n'
        )

        with init_path.open('w', encoding='utf-8') as f:
            f.write(init_code)
        print(f"Written: {init_path}")

    # Detect circular dependencies
    print("\nAnalyzing for circular imports...")
    def visit(node, path):
        if node in path:
            cycle = ' -> '.join(path[path.index(node):] + [node])
            print(f"[CIRCULAR] {cycle}")
            return
        for neighbor in import_graph.get(node, []):
            visit(neighbor, path + [node])

    for start in import_graph:
        visit(start, [])

if __name__ == '__main__':
    autopopulate_init('emulator')  # adjust as needed