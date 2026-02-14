## First Time Setup

1. install tools

```bash
make tools
```

2. install dependencies

```bash
go get
```
3. Start dependencies:

```bash
docker-compose up -d
```

4. Run migrations:

```bash
make run-migrations
```

5. shut down dependencies:

```bash
docker-compose down
```

## Run Locally (starts dependencies)

```bash
make run
```

