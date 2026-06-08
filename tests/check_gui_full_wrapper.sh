#!/bin/sh
exec "$(dirname "$0")/run-gui-test.sh" python3 "$(dirname "$0")/check_gui_full.py"
