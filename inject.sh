#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}URL Hijack Detector - Injection Tool${NC}"
echo -e "${GREEN}========================================${NC}"

if [ ! -f "URLHijackDetector.dylib" ]; then
    echo -e "${RED}Error: URLHijackDetector.dylib not found${NC}"
    echo -e "${YELLOW}Run 'make' first${NC}"
    exit 1
fi

# 越狱设备安装
if [ -d "/var/mobile/Library/MobileSubstrate/DynamicLibraries" ] 2>/dev/null; then
    echo -e "${YELLOW}Installing on jailbroken device...${NC}"
    cp URLHijackDetector.dylib /Library/MobileSubstrate/DynamicLibraries/
    echo -e "${GREEN}✅ Installed successfully${NC}"
    exit 0
fi

echo -e "${YELLOW}Usage: ./inject.sh [path/to/app.ipa]${NC}"
