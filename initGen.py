import os

def autopopulate_init(package_dir: str):
    """
    Walk through each subpackage in `package_dir`. For each directory containing
    .py files (excluding __init__.py), create or overwrite an __init__.py that:
      - Imports all symbols from each module.
      - Defines __all__ listing all module names.

    Example:
        autopopulate_init("emulator/core/hooks")
    """
    for dirpath, dirnames, filenames in os.walk(package_dir):
        # Find all .py modules except __init__.py
        modules = [f for f in filenames if f.endswith(".py") and f != "__init__.py"]
        if not modules:
            continue

        imports = []
        all_entries = []
        for module in sorted(modules):
            mod_name = os.path.splitext(module)[0]
            imports.append(f"from .{mod_name} import *")
            all_entries.append(f"    '{mod_name}',")

        content = "\n".join(
            imports
            + ["", "__all__ = ["]
            + all_entries
            + ["]", ""]
        )
        init_path = os.path.join(dirpath, "__init__.py")
        with open(init_path, "w") as init_file:
            init_file.write(content)
        print(f"Written: {init_path}")

if __name__ == "__main__":
    # Update this path to the root of the package you want to process:
    autopopulate_init("emulator/")
