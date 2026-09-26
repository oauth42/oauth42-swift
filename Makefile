.PHONY: test test-macos test-ios build

test: test-macos test-ios

test-macos:
	swift test

test-ios:
	./scripts/test-ios.sh

build:
	swift build -c release
