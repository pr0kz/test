# syntax=docker/dockerfile:1
#
# 单个 Dockerfile 出两个镜像（server / client），用 build target 区分：
#   docker build --target server -t banner-fingerprint/server .
#   docker build --target client -t banner-fingerprint/client .
# compose 里通过 build.target 指定，客户端镜像不携带任何服务端代码路径的构建产物。
#
# 打包思路：
#   构建阶段  golang:1.25-alpine + CGO_ENABLED=0，产出纯静态二进制（无 libc 依赖）
#   运行阶段  scratch —— 没有 shell、没有包管理器、没有 CA/工具链，攻击面最小（镜像 ~10MB）
# 因为运行镜像里连 curl 都没有，健康检查必须由二进制自己完成（见 cmd/server 的 -healthcheck）。

ARG GO_VERSION=1.25

FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# 依赖层先单独成层：只要 go.mod 不变，改代码不会重复拉依赖。
# 本项目零第三方依赖（纯标准库），因此在完全离线的构建环境里 `go mod download` 也不会有网络请求。
COPY go.mod ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

# -trimpath        去掉构建机的绝对路径（可复现构建 & 不泄露目录结构）
# -buildvcs=false  构建上下文里没有 .git，避免 go 探测版本库
# -ldflags "-s -w" 去掉符号表与调试信息，体积减半
# CGO_ENABLED=0    产出静态二进制；这也是能落到 scratch 的前提
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/server ./cmd/server \
 && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
      go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/client ./cmd/client \
 && ls -lh /out

# ---------------- server ----------------
FROM scratch AS server

# 约定：UID/GID 65532 = distroless 的 nonroot。compose 里同样以该 UID 运行。
COPY --from=build --chown=65532:65532 /out/server /app/server

USER 65532:65532
EXPOSE 8080

# 只监听容器端口，端口是否对外发布由 compose/编排层决定（本项目默认不发布）。
ENTRYPOINT ["/app/server"]
CMD ["-addr", ":8080", "-log-level", "info"]

# ---------------- client ----------------
FROM scratch AS client

COPY --from=build --chown=65532:65532 /out/client /app/client

USER 65532:65532

ENTRYPOINT ["/app/client"]
CMD ["-input", "/data/input.json", "-server", "http://server:8080"]
