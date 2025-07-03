# Emulator Project

This project contains a small Unicorn based emulator used to load and execute a BIOS image for experimentation. The included code provides a minimal framework for mapping ROM images and observing execution using the Unicorn and Capstone libraries.

## Installation

Use Python 3 and install the required packages:

```bash
pip install -r requirements.txt
```

## Running

Two scripts are provided as examples:

1. **Main example**

   Runs the emulator using the BIOS image in `emulator/data/BIOS_t610_1_20.bin`.
   Execute from the repository root with `PYTHONPATH` set so that the `emulator`
   package can be imported:

   ```bash
   PYTHONPATH=. python emulator/main.py
   ```

2. **Tests / demo**

   `test.py` exercises the emulator in a simple loop:

   ```bash
   python test.py
   ```

Both scripts expect the BIOS image shipped in the repository and will print
information about executed instructions and register state.
