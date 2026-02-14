## First Time Setup

1. install tools

```bash
make tools
```

2. install dependencies

```bash
go get
```
3. Start dependencies (Needs docker running)

```bash
docker-compose up -d
```

4. Run migrations

```bash
make run-migrations
```

5. shut down dependencies

```bash
docker-compose down
```

## Run Locally (starts dependencies, needs docker running)

```bash
make run
```

