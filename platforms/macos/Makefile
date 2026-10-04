CC ?= clang
CFLAGS ?= -Wall -Wextra -Werror -O2 -fblocks
FRAMEWORKS = -framework EndpointSecurity
TARGET = build/nexus-es-collector
SHADOW_TARGET = build/nexus-es-auth-shadow
ENFORCE_TARGET = build/nexus-es-auth-enforce
SOURCES = Sources/nexus_es_collector.c
SHADOW_SOURCES = Sources/nexus_es_auth_shadow.c
ENFORCE_SOURCES = Sources/nexus_es_auth_enforce.c

.PHONY: all syntax clean

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

$(ENFORCE_TARGET): $(ENFORCE_SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(ENFORCE_SOURCES) $(FRAMEWORKS) -o $(ENFORCE_TARGET)

clean:
	rm -rf build
