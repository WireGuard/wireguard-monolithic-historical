#!/bin/bash

ME="$(readlink -f "$(dirname "$(readlink -f "$0")")")"
TOOLS="$ME/../../../src/tools"

sed -i "/~~ function override insertion point ~~/r $ME/hatchet.bash" "$TOOLS/wg-quick.bash"
