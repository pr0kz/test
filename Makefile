# 开发者入口。CI 里等价于：make verify
SHELL := /bin/sh
VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help build server client test vet fmt verify up demo down logs clean

help:
	@echo "make build    # 编译 server/client 到 bin/"
	@echo "make test     # go test ./..."
	@echo "make vet      # go vet ./..."
	@echo "make verify   # vet + test + 构建镜像"
	@echo "make up       # docker compose up --build（默认不发布端口）"
	@echo "make demo     # 起服务跑一遍自测数据，client 结束即退出"
	@echo "make debug-up # 额外把 8080 绑到 127.0.0.1 便于本机 curl"
	@echo "make down     # 停掉并清理"

build: server client

server:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/server ./cmd/server

client:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/client ./cmd/client

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

verify: vet test
	docker compose build

up:
	docker compose up --build

demo:
	docker compose up --build --abort-on-container-exit --exit-code-from client client

debug-up:
	docker compose -f docker-compose.yml -f docker-compose.debug.yml up --build -d server

down:
	docker compose down --remove-orphans

logs:
	docker compose logs -f server

clean:
	rm -rf bin
	docker compose down --rmi local --remove-orphans
