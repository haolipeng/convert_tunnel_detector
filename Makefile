# 设置 Go 编译器和标准选项
GO := go
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
BINARY_NAME := convert-tunnel-detector

# 版本信息
VERSION := 1.0.0
BUILD_TIME := $(shell date "+%F %T")
COMMIT_SHA1 := $(shell git rev-parse HEAD)

# 编译选项
LDFLAGS := -ldflags "-X main.Version=${VERSION} -X 'main.BuildTime=${BUILD_TIME}' -X main.GitCommit=${COMMIT_SHA1}"

.PHONY: all build clean test

# 默认目标
all: build

# 编译
build:
	@echo "Building ${BINARY_NAME}..."
	@${GO} build ${LDFLAGS} -o bin/${BINARY_NAME} cmd/main.go

# 编译优化版本
build-release:
	@echo "Building release version..."
	@${GO} build -ldflags '-s -w' ${LDFLAGS} -o bin/${BINARY_NAME} cmd/main.go

# 运行测试
test:
	@echo "Running tests..."
	@${GO} test -v ./...

# 清理编译文件
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@${GO} clean

# 安装依赖
deps:
	@echo "Installing dependencies..."
	@${GO} mod tidy
	@${GO} mod verify

# 检查代码格式
fmt:
	@echo "Formatting code..."
	@${GO} fmt ./...

# 运行代码检查
lint:
	@echo "Running linter..."
	@golangci-lint run ./... 
