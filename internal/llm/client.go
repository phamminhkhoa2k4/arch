// Package llm calls an OpenAI-compatible chat completions API to
// explain one component's verdict or hypothesise about an unknown
// script. It is the product's only outbound HTTP client besides the
// docker socket client, it is off by default (no key, no request),
// and it never writes to the evidence store.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Environment configuration. Missing API key disables the explainer:
// --explain errors instead of silently skipping.
const (
	EnvBaseURL = "ARCHAEOLOGIST_LLM_BASE_URL"
	EnvAPIKey  = "ARCHAEOLOGIST_LLM_API_KEY"
	EnvModel   = "ARCHAEOLOGIST_LLM_MODEL"

	// DefaultBaseURL targets the OpenAI API; any OpenAI-compatible
	// endpoint (Ollama, OpenRouter, ...) works via the env override.
	DefaultBaseURL = "https://api.openai.com/v1"
	DefaultModel   = "gpt-4o-mini"

	// requestTimeout bounds one chat call.
	requestTimeout = 30 * time.Second
)

// ErrNotConfigured reports a missing API key: the user asked for an
// explanation but did not configure a provider.
var ErrNotConfigured = errors.New(
	"llm explainer is not configured: set " + EnvAPIKey +
		" (and optionally " + EnvBaseURL + ", " + EnvModel + ")")

// Config is the resolved explainer configuration.
type Config struct {
	BaseURL string
	APIKey  string
	Model   string
}

// LoadConfig reads the explainer configuration from the environment.
func LoadConfig() Config {
	cfg := Config{
		BaseURL: os.Getenv(EnvBaseURL),
		APIKey:  os.Getenv(EnvAPIKey),
		Model:   os.Getenv(EnvModel),
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.Model == "" {
		cfg.Model = DefaultModel
	}
	return cfg
}

// Client talks to one OpenAI-compatible chat endpoint.
type Client struct {
	cfg Config
	hc  *http.Client
}

// New builds a client for cfg.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, hc: &http.Client{Timeout: requestTimeout}}
}

// chatRequest is the OpenAI chat-completions request body.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the subset of the response we consume.
type chatResponse struct {
	Choices []chatChoice `json:"choices"`
	Error   *chatError   `json:"error"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatError struct {
	Message string `json:"message"`
}

// Explain sends the system prompt plus the (already redacted) user
// payload and returns the assistant's text. A missing API key is
// ErrNotConfigured and performs no network call.
func (c *Client) Explain(ctx context.Context, system, userPayload string) (string, error) {
	if c.cfg.APIKey == "" {
		return "", ErrNotConfigured
	}
	body, err := json.Marshal(chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: userPayload},
		},
	})
	if err != nil {
		return "", fmt.Errorf("llm request marshal: %w", err)
	}
	url := c.cfg.BaseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("llm response read: %w", err)
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("llm response parse: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("llm api error: %s", parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm http %d: %s", resp.StatusCode, snippet(raw))
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("llm response has no choices")
	}
	return parsed.Choices[0].Message.Content, nil
}

// snippet shortens an unexpected body for error messages.
func snippet(raw []byte) string {
	const max = 200
	s := string(raw)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
