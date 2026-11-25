#!/bin/zsh
set -euo pipefail
ao_project="${0:A:h}"
mkdir -p "$ao_project/build"
xcrun clang -O2 -fobjc-arc -fblocks -mmacosx-version-min=14.2 \
  -Wno-deprecated-declarations -Wno-nullability-completeness \
  "$ao_project/Sources/main.m" "$ao_project/Sources/Store.m" \
  "$ao_project/Sources/FileHistory.m" "$ao_project/Sources/Sensors.m" "$ao_project/Sources/Network.m" \
  "$ao_project/Sources/Integrity.m" "$ao_project/Sources/Guard.m" \
  -framework Foundation -framework AppKit -framework CoreGraphics \
  -framework CoreAudio -framework CoreServices -framework IOKit \
  -framework Security -lsqlite3 -o "$ao_project/build/activity-observer"
codesign --force --sign - --options runtime,hard,kill "$ao_project/build/activity-observer"
"$ao_project/build/activity-observer" self-test
"$ao_project/build/activity-observer" integrity-self-test
