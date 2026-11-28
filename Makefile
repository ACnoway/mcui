.PHONY: build build-frontend build-go dist-stub test clean

dist-stub:
	@mkdir -p internal/master/dist
	@test -f internal/master/dist/index.html || printf '<!doctype html><title>mcui</title>' > internal/master/dist/index.html

build-frontend:
	cd frontend && pnpm install && pnpm run build

build-go: dist-stub
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/mcui-master ./cmd/master
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/mcui-agent ./cmd/agent

build: build-frontend build-go

test: dist-stub
	go test -race ./...

clean:
	rm -rf bin internal/master/dist/assets internal/master/dist/index.html
