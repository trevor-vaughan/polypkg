// Package config provides layered configuration loading for polypkg.
// Precedence (low to high authority):
//  1. Built-in defaults
//  2. Config file (ConfigPaths are searched in order; the first "config.yaml"
//     found is used — viper does not merge multiple files)
//  3. Environment variables (prefixed with EnvPrefix)
//  4. CLI flags (bound by callers)
package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Scope identifies which scope the config governs.
type Scope int

const (
	// ScopeUser is the per-user config scope.
	ScopeUser Scope = iota
	// ScopeSystem is the system-wide config scope.
	ScopeSystem
)

// Options controls how Load assembles the configuration.
type Options struct {
	// Scope is reserved for future scope-specific defaults; Load does not
	// branch on it yet.
	Scope Scope
	// ConfigPaths are directories searched (in order) for "config.yaml".
	ConfigPaths []string
	// EnvPrefix enables the environment-variable layer; an empty value
	// disables env overrides entirely.
	EnvPrefix string
}

// Load builds a Viper configuration with all layers applied.
func Load(opts Options) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	setDefaults(v)

	for _, path := range opts.ConfigPaths {
		v.AddConfigPath(path)
	}
	if len(opts.ConfigPaths) > 0 {
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
	}

	if opts.EnvPrefix != "" {
		v.SetEnvPrefix(opts.EnvPrefix)
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()
	}

	return v, nil
}

// setDefaults registers defaults for the keys polypkg actually reads. A key
// belongs here only once a consumer exists.
//
// viper accepts unknown keys from a config file without complaint, so a
// default registered ahead of its consumer is worse than no entry at all: it
// makes the setting look supported while nothing acts on it. lock.contention,
// lock.stale_age_threshold, retention.count, retention.age and audit.sinks.*
// were registered here with no reader anywhere in the tree, and retention in
// particular is configured in the profile (see apply.go), so the entries
// pointed operators at the wrong layer entirely.
func setDefaults(v *viper.Viper) {
	v.SetDefault("revocation.near_expiry_threshold", "14d")
	v.SetDefault("bridge.enabled", true)
	v.SetDefault("completion.enabled", true)
	v.SetDefault("desktop.enabled", true)
	v.SetDefault("mime.enabled", true)
}
