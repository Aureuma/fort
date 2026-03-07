package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fort/internal/agent"
)

func envOr(name, fallback string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	return v
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func floatEnv(name string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	var out float64
	if _, err := fmt.Sscanf(v, "%f", &out); err != nil {
		return fallback
	}
	return out
}

func main() {
	fs := flag.NewFlagSet("fort-agent", flag.ExitOnError)
	host := fs.String("host", envOr("FORT_HOST", "http://127.0.0.1:8088"), "fort API host")
	refreshTokenFile := fs.String("refresh-token-file", envOr("FORT_REFRESH_TOKEN_FILE", ""), "path to refresh token file (0600)")
	tokenPath := fs.String("token-path", envOr("FORT_TOKEN_PATH", "/tmp/fort/access.token"), "access token output path")
	refreshRatio := fs.Float64("refresh-ratio", floatEnv("FORT_AGENT_REFRESH_RATIO", 0.70), "refresh ratio for access token lifetime")
	jitter := fs.Duration("jitter", durationEnv("FORT_AGENT_JITTER", 10*time.Second), "refresh jitter window")
	minSleep := fs.Duration("min-sleep", durationEnv("FORT_AGENT_MIN_SLEEP", 5*time.Second), "minimum sleep duration")
	maxBackoff := fs.Duration("max-backoff", durationEnv("FORT_AGENT_MAX_BACKOFF", 30*time.Second), "max retry backoff")
	httpTimeout := fs.Duration("http-timeout", durationEnv("FORT_AGENT_HTTP_TIMEOUT", 10*time.Second), "HTTP timeout")
	once := fs.Bool("once", false, "refresh once then exit")
	fs.Parse(os.Args[1:])

	rt, err := agent.New(agent.Config{
		Host:             *host,
		RefreshTokenFile: *refreshTokenFile,
		TokenPath:        *tokenPath,
		RefreshRatio:     *refreshRatio,
		Jitter:           *jitter,
		MinSleep:         *minSleep,
		MaxBackoff:       *maxBackoff,
		HTTPTimeout:      *httpTimeout,
		Once:             *once,
	})
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("fort-agent starting host=%s token_path=%s once=%t", strings.TrimRight(*host, "/"), *tokenPath, *once)
	if err := rt.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("runtime: %v", err)
	}
	log.Printf("fort-agent stopped")
}
