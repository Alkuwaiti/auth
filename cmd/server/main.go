package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

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

	envFlag := flag.String("env", "local", "environment to use (local, dev, staging, prod)")
	jurFlag := flag.String("jur", "", "jur to use (bhr, uae, tur)")
	flag.Parse()

	cfg := config.Load(strings.ToLower(*envFlag), strings.ToLower(*jurFlag))

	fmt.Println(ctx)
	fmt.Println(cfg.LogLevel)
	fmt.Println(cfg.DatabaseURL)
	fmt.Println(cfg.TracingCollector)
	fmt.Println(cfg.Environment)
	fmt.Println(cfg.Jurisdiction)
}
