.PHONY: test build run tools

check-brew:
	@which brew || ( \
		echo "Homebrew not found. Installing Homebrew..." && \
		/bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
	)

# Note: run this to get all available tools in this project.
tools: check-brew
	@which go || (echo "Installing go..." && brew install go)
	@which mockery || (echo "Installing mockery..." && brew install mockery)
	@which protoc || (echo "Installing protoc..." && brew install protobuf)
	@which protoc-gen-go || (echo "Installing protoc-gen-go..." && go install google.golang.org/protobuf/cmd/protoc-gen-go@latest)
	@which protoc-gen-go-grpc || (echo "Installing protoc-gen-go-grpc..." && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest)
	@which golangci-lint || (echo "Installing golangci-lint..." && brew install golangci-lint)
	@which migrate || (echo "Installing migrate..." && go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest)
	@which docker ||  (echo "Installing docker..." && brew install docker)
	@which sqlc || (echo "Installing sqlc..." && brew install sqlc)

clean:
	@echo "cleaning up .bin/"
	rm -rf bin/

short-test:
	@echo "Running short test"
	go test -short -race ./...

test:
	@echo "Running test"
	go test -race -p 12 ./...

test-integration:
	@echo "Running Integration tests..."
	go test -tags=integration ./internal/... -v

test-function:
	@echo "testing passed function: $(METHOD)"
	go test -tags=integration ./internal/auth -run $(METHOD)

build:
	@echo "Building..."
	go build -ldflags "-X main.commit=`git rev-parse HEAD` -X main.ref=`git rev-parse --abbrev-ref HEAD` -X main.version=`git describe --tags --always`" -o ./bin/server ./cmd/server

run:
	@echo "Running locally (--env local flag passed)"
	@docker-compose up -d
	@$(MAKE) _run_server

_run_server:
	@bash -c 'trap "echo Stopping docker-compose; docker-compose stop" EXIT; \
		go run -ldflags "-X main.commit=`git rev-parse HEAD` -X main.ref=`git rev-parse --abbrev-ref HEAD` -X main.version=`git describe --tags --always`" \
		./cmd/server \
		--env local'

mocks:
	@echo "Generating mocks..."
	@mockery

lint: 
	@echo "Running linter..."
	golangci-lint run --build-tags=integration

create-migrations:
	migrate create -ext sql -dir internal/db/migrations $${name:-migration}

proto:
	@echo "Generating proto...\n"
	protoc --go_out=. --go_opt=module=github.com/alkuwaiti/auth \
		--go-grpc_out=. --go-grpc_opt=module=github.com/alkuwaiti/auth \
		./.proto/*.proto
	@echo ""

DB_URL ?= postgres://localuser:veryhardpassword123@localhost:5432/authdb?sslmode=disable
run-migrations:
	migrate \
  -path internal/db/migrations \
  -database $(DB_URL) \
  up

rollback-last-migration:
	migrate \
  -path internal/db/migrations \
  -database $(DB_URL) \
  down 1

sqlc:
	sqlc generate
