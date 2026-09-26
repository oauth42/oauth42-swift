#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
simulator_id="${IOS_SIMULATOR_ID:-}"
if [ -z "$simulator_id" ]; then
  simulator_id="$(xcrun simctl list devices available -j | python3 -c '
import json, re, sys
runtimes = json.load(sys.stdin)["devices"]
for runtime in sorted(runtimes, key=lambda x: [int(n) for n in re.findall(r"\d+", x)], reverse=True):
    if ".iOS-" in runtime:
        for device in runtimes[runtime]:
            if device.get("isAvailable") and device["name"].startswith("iPhone"):
                print(device["udid"])
                sys.exit(0)
sys.exit("No available iPhone simulator; install an iOS runtime in Xcode")
')"
fi
exec xcodebuild test -project Tests/iOSHost/SecurityTests.xcodeproj -scheme SecurityTests \
  -destination "platform=iOS Simulator,id=$simulator_id" -derivedDataPath .build/ios-tests
