package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/viper"
)

type config struct {
	LogLevel string         `json:"logLevel,omitempty"`
	UI       uiConfig       `json:"ui,omitempty"`
	Cors     corsConfig     `json:"cors,omitempty"`
	Cache    cacheConfig    `json:"cache,omitempty"`
	Server   serverConfig   `json:"server,omitempty"`
	Database databaseConfig `json:"database,omitempty"`
	Metrics  *metrics       `json:"metrics,omitempty"`
}

type uiConfig struct {
	Enabled bool `json:"enabled"`
}

type corsConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
}

type memoryCacheConfig struct {
	Enabled bool `json:"enabled"`
	Items   int  `json:"items,omitempty"`
}

type cacheConfig struct {
	Memory memoryCacheConfig `json:"memory,omitempty"`
}

type serverConfig struct {
	Host     string `json:"host,omitempty"`
	HTTPPort int    `json:"httpPort,omitempty"`
	GRPCPort int    `json:"grpcPort,omitempty"`
}

type databaseConfig struct {
	MigrationsPath string `json:"migrationsPath,omitempty"`
	URL            string `json:"url,omitempty"`
}

type metrics struct {
	requestCounter  *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	responseSize    *prometheus.HistogramVec
}

func newMetrics() *metrics {
	return &metrics{
		requestCounter: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "prometheus_http_requests_total",
				Help: "Counter of HTTP requests.",
			},
			[]string{"handler", "code"},
		),
		requestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "prometheus_http_request_duration_seconds",
				Help:    "Histogram of latencies for HTTP requests.",
				Buckets: []float64{.1, .2, .4, 1, 3, 8, 20, 60, 120},
			},
			[]string{"handler"},
		),
		responseSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "prometheus_http_response_size_bytes",
				Help:    "Histogram of response size for HTTP requests.",
				Buckets: prometheus.ExponentialBuckets(100, 10, 8),
			},
			[]string{"handler"},
		),
	}
}

func defaultConfig() *config {
	return &config{
		LogLevel: "INFO",

		UI: uiConfig{
			Enabled: true,
		},

		Cors: corsConfig{
			Enabled:        false,
			AllowedOrigins: []string{"*"},
		},

		Cache: cacheConfig{
			Memory: memoryCacheConfig{
				Enabled: false,
				Items:   500,
			},
		},

		Server: serverConfig{
			Host:     "0.0.0.0",
			HTTPPort: 8080,
			GRPCPort: 9000,
		},

		Database: databaseConfig{
			URL:            "file:/var/opt/flipt/flipt.db",
			MigrationsPath: "/etc/flipt/config/migrations",
		},

		Metrics: newMetrics(),
	}
}

func (m *metrics) instrumentMiddleware(next http.Handler) http.HandlerFunc {
	return promhttp.InstrumentHandlerCounter(
		m.requestCounter,
		promhttp.InstrumentHandlerDuration(
			m.requestDuration,
			promhttp.InstrumentHandlerResponseSize(
				m.responseSize,
				next,
			),
		),
	)
}

const (
	// Logging
	cfgLogLevel = "log.level"

	// UI
	cfgUIEnabled = "ui.enabled"

	// CORS
	cfgCorsEnabled        = "cors.enabled"
	cfgCorsAllowedOrigins = "cors.allowed_origins"

	// Cache
	cfgCacheMemoryEnabled = "cache.memory.enabled"
	cfgCacheMemoryItems   = "cache.memory.items"

	// Server
	cfgServerHost     = "server.host"
	cfgServerHTTPPort = "server.http_port"
	cfgServerGRPCPort = "server.grpc_port"

	// DB
	cfgDBURL            = "db.url"
	cfgDBMigrationsPath = "db.migrations.path"
)

func configure() (*config, error) {
	viper.SetEnvPrefix("FLIPT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetConfigFile(cfgPath)

	if err := viper.ReadInConfig(); err != nil {
		return nil, errors.Wrap(err, "loading config")
	}

	cfg := defaultConfig()

	// Logging
	if viper.IsSet(cfgLogLevel) {
		cfg.LogLevel = viper.GetString(cfgLogLevel)
	}

	// UI
	if viper.IsSet(cfgUIEnabled) {
		cfg.UI.Enabled = viper.GetBool(cfgUIEnabled)
	}

	// CORS
	if viper.IsSet(cfgCorsEnabled) {
		cfg.Cors.Enabled = viper.GetBool(cfgCorsEnabled)

		if viper.IsSet(cfgCorsAllowedOrigins) {
			cfg.Cors.AllowedOrigins = viper.GetStringSlice(cfgCorsAllowedOrigins)
		}
	}

	// Cache
	if viper.IsSet(cfgCacheMemoryEnabled) {
		cfg.Cache.Memory.Enabled = viper.GetBool(cfgCacheMemoryEnabled)

		if viper.IsSet(cfgCacheMemoryItems) {
			cfg.Cache.Memory.Items = viper.GetInt(cfgCacheMemoryItems)
		}
	}

	// Server
	if viper.IsSet(cfgServerHost) {
		cfg.Server.Host = viper.GetString(cfgServerHost)
	}
	if viper.IsSet(cfgServerHTTPPort) {
		cfg.Server.HTTPPort = viper.GetInt(cfgServerHTTPPort)
	}
	if viper.IsSet(cfgServerGRPCPort) {
		cfg.Server.GRPCPort = viper.GetInt(cfgServerGRPCPort)
	}

	// DB
	if viper.IsSet(cfgDBURL) {
		cfg.Database.URL = viper.GetString(cfgDBURL)
	}
	if viper.IsSet(cfgDBMigrationsPath) {
		cfg.Database.MigrationsPath = viper.GetString(cfgDBMigrationsPath)
	}

	return cfg, nil
}

func (c *config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out, err := json.Marshal(c)
	if err != nil {
		logger.WithError(err).Error("getting config")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(out); err != nil {
		logger.WithError(err).Error("writing response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

type info struct {
	Version   string `json:"version,omitempty"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"buildDate,omitempty"`
	GoVersion string `json:"goVersion,omitempty"`
}

func (i info) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	out, err := json.Marshal(i)
	if err != nil {
		logger.WithError(err).Error("getting metadata")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err = w.Write(out); err != nil {
		logger.WithError(err).Error("writing response")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
