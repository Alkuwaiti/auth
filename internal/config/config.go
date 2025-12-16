// Package config provides configuration values based on loaded environment.
package config

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

var configs embed.FS

var cfg Config

type Config struct {
	loaded           bool
	Env              string
	LogLevel         string
	TracingCollector string
	DatabaseURL      string
}

func Load() Config {
	if !cfg.loaded {
		envFlag := flag.String("env", "local", "environment to use (local, dev, staging, prod)")
		jurFlag := flag.String("jur", "", "jur to use (bhr, uae, tur)")
		flag.Parse()

		env := strings.ToLower(*envFlag)
		jur := strings.ToLower(*jurFlag)

		switch env {
		case "local", "dev", "staging", "prod":
		default:
			panic(fmt.Sprintf("Invalid env provided: %s", env))
		}

		if jur != "" {
			switch jur {
			case "bhr", "uae", "tur":
			default:
				panic(fmt.Sprintf("Invalid jur provided: %s", jur))
			}
		}

		v := viper.NewWithOptions(
			viper.WithLogger(slog.Default()),
			viper.KeyDelimiter("_"),
		)

		v.SetConfigType("yaml")
		v.AllowEmptyEnv(true)
		v.SetDefault("loglevel", "info")

		// Include base configuration
		mergeConfigFile(v, ".config/base.yml")

		// Include environment and region-specific configuration
		envFile := fmt.Sprintf(".config/%s.yml", env)
		mergeConfigFile(v, envFile)

		if jur != "" {
			jurFile := fmt.Sprintf(".config/%s.yml", jur)
			mergeConfigFile(v, jurFile)

			envJurFile := fmt.Sprintf(".config/%s_%s.yml", env, jur)
			mergeConfigFile(v, envJurFile)
		}

		v.AutomaticEnv()
		v.Set("Env", env)
		v.Set("Jurisdiction", jur)

		if err := v.Unmarshal(&cfg); err != nil {
			panic(err)
		}

		cfg.loaded = true
	}

	return cfg
}

func mergeConfigFile(v *viper.Viper, filename string) {
	data, err := configs.ReadFile(filename)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		panic(err)
	}
	if err := v.MergeConfig(bytes.NewReader(data)); err != nil {
		panic(err)
	}
}
