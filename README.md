# parser_mac_spin_dump
parser mac spindump symbol


parser mac spindump symbol

using atos to parse mac spindump symbol

* test:
1. indicate the spindump file path and dsym file path
python main.py path/spindump.txt libxxx.dSYM/Contents/Resources/DWARF/libxxx.dylib

2. indicate the spindump file path and dsym file directory
python main.py path/spindump.txt dsym file directory

this file need run in mac os