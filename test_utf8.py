import os

def scan_encoding_issues(path):
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".py"):
                full_path = os.path.join(root, f)
                try:
                    with open(full_path, encoding="utf-8") as fobj:
                        fobj.read()
                except UnicodeDecodeError:
                    print("❌ Encoding issue:", full_path)

scan_encoding_issues("D:/Workspaces/Python/EmulatorTest/emulator")