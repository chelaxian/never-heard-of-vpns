ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:17.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NeverHeardOfVPNs

$(TWEAK_NAME)_FILES = Tweak.mm vendor/fishhook/fishhook.c
$(TWEAK_NAME)_CFLAGS = -fobjc-arc
$(TWEAK_NAME)_CCFLAGS = -std=c++17
$(TWEAK_NAME)_FRAMEWORKS = Foundation CFNetwork Network NetworkExtension SystemConfiguration

include $(THEOS_MAKE_PATH)/tweak.mk
