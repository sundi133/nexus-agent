CC ?= clang
CFLAGS ?= -Wall -Wextra -Werror -O2
FRAMEWORKS = -framework EndpointSecurity
TARGET = build/nexus-es-collector
SHADOW_TARGET = build/nexus-es-auth-shadow
SOURCES = Sources/nexus_es_collector.c
SHADOW_SOURCES = Sources/nexus_es_auth_shadow.c

.PHONY: all clean

all: $(TARGET) $(SHADOW_TARGET)

$(TARGET): $(SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(SOURCES) $(FRAMEWORKS) -o $(TARGET)

$(SHADOW_TARGET): $(SHADOW_SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(SHADOW_SOURCES) $(FRAMEWORKS) -o $(SHADOW_TARGET)

clean:
	rm -rf build
