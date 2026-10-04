CC ?= clang
CFLAGS ?= -Wall -Wextra -Werror -O2
FRAMEWORKS = -framework EndpointSecurity
TARGET = build/nexus-es-collector
SOURCES = Sources/nexus_es_collector.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	mkdir -p build
	$(CC) $(CFLAGS) $(SOURCES) $(FRAMEWORKS) -o $(TARGET)

clean:
	rm -rf build
