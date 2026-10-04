CC ?= clang
CFLAGS ?= -Wall -Wextra -Werror -O2 -fblocks
FRAMEWORKS = -framework EndpointSecurity
TARGET = build/nexus-es-collector
SHADOW_TARGET = build/nexus-es-auth-shadow
ENFORCE_TARGET = build/nexus-es-auth-enforce
SOURCES = Sources/nexus_es_collector.c
SHADOW_SOURCES = Sources/nexus_es_auth_shadow.c
ENFORCE_SOURCES = Sources/nexus_es_auth_enforce.c

.PHONY: all syntax package-syntax clean

all: $(TARGET) $(SHADOW_TARGET) $(ENFORCE_TARGET)

syntax:
	xcrun --sdk macosx clang $(CFLAGS) -fsyntax-only $(SOURCES)
	xcrun --sdk macosx clang $(CFLAGS) -fsyntax-only $(SHADOW_SOURCES)
	xcrun --sdk macosx clang $(CFLAGS) -fsyntax-only $(ENFORCE_SOURCES)

$(TARGET): $(SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(SOURCES) $(FRAMEWORKS) -o $(TARGET)

$(SHADOW_TARGET): $(SHADOW_SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(SHADOW_SOURCES) $(FRAMEWORKS) -o $(SHADOW_TARGET)

package-syntax:
	xcrun swiftc -typecheck -swift-version 5 Package/HostApp/Sources/*.swift -framework SwiftUI -framework SystemExtensions -framework NetworkExtension
	xcrun swiftc -typecheck -swift-version 5 Package/FilterData/Sources/*.swift -framework NetworkExtension
	xcrun --sdk macosx clang $(CFLAGS) -I../../core/include -fsyntax-only Package/SystemExtension/Sources/main.c
	plutil -lint Package/HostApp/Info.plist Package/HostApp/NexusAgent.entitlements Package/SystemExtension/Info.plist Package/SystemExtension/NexusEndpointExtension.entitlements Package/FilterData/Info.plist Package/FilterData/NexusFilterData.entitlements
	plutil -lint Deployment/SystemExtensions.mobileconfig.template Deployment/PPPC-FullDiskAccess.mobileconfig.template Deployment/WebContentFilter.mobileconfig.template Deployment/ai.votal.nexus.runtime.plist
	bash -n Deployment/install-runtime.sh Deployment/uninstall-runtime.sh
	ruby -e 'require "yaml"; YAML.load_file("Package/project.yml"); puts "project.yml OK"'

$(ENFORCE_TARGET): $(ENFORCE_SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(ENFORCE_SOURCES) $(FRAMEWORKS) -o $(ENFORCE_TARGET)

clean:
	rm -rf build
