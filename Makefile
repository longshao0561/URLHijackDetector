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
CFLAGS += -fvisibility=hidden

all: $(NAME).dylib

$(NAME).dylib: $(NAME).m
	@echo "=========================================="
	@echo "Building URLHijackDetector"
	@echo "=========================================="
	@echo "SDK: $(IOS_SDK)"
	@echo "Archs: $(ARCHS)"
	@echo "Min Version: $(IOS_VERSION_MIN)"
	@echo "------------------------------------------"
	$(CC) $(CFLAGS) -o $@ $<
	@echo "------------------------------------------"
	@echo "Build complete: $@"
	@file $@
	@echo "=========================================="

clean:
	rm -f $(NAME).dylib

install: $(NAME).dylib
	scp $< root@localhost:/Library/MobileSubstrate/DynamicLibraries/

.PHONY: all clean install
