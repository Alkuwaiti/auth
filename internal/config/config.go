// Package config provides configuration values based on loaded environment.
package config

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/spf13/viper"
)

//go:embed .config
var configs embed.FS

var (
	cfg    Config
	loaded bool
)

type Config struct {
	Environment          string
	LogLevel             string
	TracingCollector     string
	DatabaseURL          string
	JWTKey               string
	OTLPEndpoint         string
	RefreshEnabled       bool
	AESKey               string
	AppName              string
	MaxChallengeAttempts int
	GoogleConfig         googleConfig
	KafkaConfig          kafkaConfig
}

type googleConfig struct {
	ClientID, ClientSecret, RedirectURL, StateSecret string
}

type kafkaConfig struct {
	Brokers  []string
	Topic    string
	DLQTopic string
	Interval int
}

func Load(env string) Config {
	if !loaded {
		switch env {
		case "local", "dev", "staging", "prod":
		default:
			panic(fmt.Sprintf("Invalid env provided: %s", env))
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

		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
		v.Set("Environment", env)

		if err := v.Unmarshal(&cfg); err != nil {
			panic(err)
		}

		loaded = true
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
