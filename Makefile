# Makefile
NAME = URLHijackDetector
IOS_SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
IOS_VERSION_MIN = 12.0
ARCHS = arm64 arm64e

CC = clang
CFLAGS = -dynamiclib
CFLAGS += $(addprefix -arch ,$(ARCHS))
CFLAGS += -framework Foundation
CFLAGS += -framework ObjectiveC
CFLAGS += -framework CFNetwork
CFLAGS += -miphoneos-version-min=$(IOS_VERSION_MIN)
CFLAGS += -isysroot $(IOS_SDK)
CFLAGS += -O2 -Wall -fobjc-arc
CFLAGS += -D__IPHONE_OS_VERSION_MIN_REQUIRED=120000

all: $(NAME).dylib

$(NAME).dylib: $(NAME).m
	@echo "Building for iOS $(IOS_VERSION_MIN)..."
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Build complete: $@"
	@file $@

clean:
	rm -f $(NAME).dylib

info:
	@echo "SDK: $(IOS_SDK)"
	@echo "Archs: $(ARCHS)"
	@echo "Min Version: $(IOS_VERSION_MIN)"

.PHONY: all clean info
