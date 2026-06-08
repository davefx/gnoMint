#!/bin/sh
exec "$(dirname "$0")/run-headless.sh" "$(dirname "$0")/check_workflows"
