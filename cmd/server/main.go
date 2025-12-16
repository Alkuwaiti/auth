package main

import (
	"context"
	"fmt"

	"github.com/alkuwaiti/auth/internal/config"
)

var (
	commit  string
	ref     string
	version string
	name    = "auth-service"
)

func main() {
	ctx := context.Background()
	cfg := config.Load()

	fmt.Println(ctx)
	fmt.Println(cfg.LogLevel)
	fmt.Println(cfg.DatabaseURL)
	fmt.Println(cfg.TracingCollector)
}
