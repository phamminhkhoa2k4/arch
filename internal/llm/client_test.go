package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A configured client posts system + user messages and returns the
// assistant text from the canned response.
func TestExplainChat(t *testing.T) {
	var gotAuth, gotPath string
	var gotReq chatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(chatResponse{Choices: []chatChoice{
			{Message: chatMessage{Role: "assistant", Content: "explained"}},
		}})
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, APIKey: "k", Model: "m"})
	got, err := c.Explain(context.Background(), "sys", "payload")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if got != "explained" {
		t.Errorf("text = %q, want explained", got)
	}
	if gotAuth != "Bearer k" {
		t.Errorf("auth = %q, want Bearer k", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotReq.Model != "m" || len(gotReq.Messages) != 2 {
		t.Errorf("request = %+v", gotReq)
	}
	if gotReq.Messages[0].Role != "system" || gotReq.Messages[1].Content != "payload" {
		t.Errorf("messages = %+v", gotReq.Messages)
	}
}

// A missing API key is ErrNotConfigured and performs no request.
func TestExplainNoKey(t *testing.T) {
	requested := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL})
	if _, err := c.Explain(context.Background(), "s", "u"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	if requested {
		t.Error("request reached the server without an API key")
	}
}

// A non-200 response surfaces as an error carrying the status.
func TestExplainHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"bad token"}}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, APIKey: "k"})
	if _, err := c.Explain(context.Background(), "s", "u"); err == nil {
		t.Fatal("500 must error")
	}
}

// LoadConfig applies the documented defaults.
func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv(EnvBaseURL, "")
	t.Setenv(EnvModel, "")
	t.Setenv(EnvAPIKey, "secret")
	cfg := LoadConfig()
	if cfg.BaseURL != DefaultBaseURL || cfg.Model != DefaultModel {
		t.Errorf("cfg = %+v", cfg)
	}
}
