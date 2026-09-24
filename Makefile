.PHONY: build test vet lint dist dev-server dev-agent clean

build:
	go build -o bin/votal-agent ./cmd/votal-agent
	go build -o bin/votal-devserver ./cmd/votal-devserver

test:
	go test -race ./...

# Vet every target OS: platform code is behind build tags.
vet:
	GOOS=linux   go vet ./...
	GOOS=darwin  go vet ./...
	GOOS=windows go vet ./...

lint: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

dist:
	scripts/build.sh

dev-server: build
	bin/votal-devserver -policy examples/policy.json

dev-agent: build
	bin/votal-agent run -config examples/config.dev.json

clean:
	rm -rf bin dist .votal-state
