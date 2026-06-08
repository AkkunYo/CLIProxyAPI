package executor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// buildTestEventFrame builds a minimal valid AWS Event Stream binary frame.
func buildTestEventFrame(jsonPayload []byte) []byte {
	headersLen := uint32(0)
	payloadLen := uint32(len(jsonPayload))
	totalLen := uint32(12 + headersLen + payloadLen + 4) // prelude(12) + payload + trailing CRC(4)

	frame := make([]byte, totalLen)
	binary.BigEndian.PutUint32(frame[0:], totalLen)
	binary.BigEndian.PutUint32(frame[4:], headersLen)
	binary.BigEndian.PutUint32(frame[8:], 0) // prelude CRC (parser ignores)
	copy(frame[12:], jsonPayload)
	// trailing message CRC is zeroed (parser ignores)
	return frame
}

func TestKiroMapModel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"claude-sonnet-4-6", "claude-sonnet-4.6"},
		{"claude-opus-4-7", "claude-opus-4.7"},
		{"claude-haiku-4-5", "claude-haiku-4.5"},
		{"claude-sonnet-4.6", "claude-sonnet-4.6"},
		{"unknown-model", "claude-sonnet-4.5"},
	}
	for _, tc := range cases {
		got := kiroMapModel(tc.in)
		if got != tc.want {
			t.Errorf("kiroMapModel(%q): got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestKiroMachineID_Deterministic(t *testing.T) {
	a := kiroMachineID("arn:aws:foo", "cid123")
	b := kiroMachineID("arn:aws:foo", "cid123")
	if a != b {
		t.Errorf("kiroMachineID not deterministic: %q vs %q", a, b)
	}
	c := kiroMachineID("", "")
	if a == c {
		t.Error("expected different machineID for different inputs")
	}
}

func TestTranslateOpenAIToKiro_BasicMessage(t *testing.T) {
	input := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hello"}],"max_tokens":1024}`)
	out, err := translateOpenAIToKiro(input, "claude-sonnet-4.6")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload kiroRequest
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("invalid kiro payload JSON: %v", err)
	}
	if payload.ConversationState.CurrentMessage.UserInputMessage.Content != "hello" {
		t.Errorf("content: got %q, want %q",
			payload.ConversationState.CurrentMessage.UserInputMessage.Content, "hello")
	}
	if payload.ConversationState.CurrentMessage.UserInputMessage.ModelID != "claude-sonnet-4.6" {
		t.Errorf("modelId: got %q, want %q",
			payload.ConversationState.CurrentMessage.UserInputMessage.ModelID, "claude-sonnet-4.6")
	}
	if payload.InferenceConfig == nil || payload.InferenceConfig.MaxTokens != 1024 {
		t.Error("expected inferenceConfig.maxTokens=1024")
	}
}

func TestTranslateOpenAIToKiro_SystemPrompt(t *testing.T) {
	input := []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"system","content":"be helpful"},{"role":"user","content":"hi"}]}`)
	out, err := translateOpenAIToKiro(input, "claude-sonnet-4.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload kiroRequest
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("invalid payload: %v", err)
	}
	content := payload.ConversationState.CurrentMessage.UserInputMessage.Content
	if !strings.Contains(content, "be helpful") {
		t.Errorf("expected system prompt in content, got: %q", content)
	}
	if !strings.Contains(content, "hi") {
		t.Errorf("expected user message in content, got: %q", content)
	}
}

func TestTranslateOpenAIToKiro_MultiTurnHistory(t *testing.T) {
	input := []byte(`{"messages":[
		{"role":"user","content":"q1"},
		{"role":"assistant","content":"a1"},
		{"role":"user","content":"q2"}
	]}`)
	out, err := translateOpenAIToKiro(input, "claude-sonnet-4.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var payload kiroRequest
	if err := json.Unmarshal(out, &payload); err != nil {
		t.Fatalf("invalid payload: %v", err)
	}
	if len(payload.ConversationState.History) != 2 {
		t.Errorf("expected 2 history entries, got %d", len(payload.ConversationState.History))
	}
	if payload.ConversationState.CurrentMessage.UserInputMessage.Content != "q2" {
		t.Errorf("expected current content %q, got %q", "q2",
			payload.ConversationState.CurrentMessage.UserInputMessage.Content)
	}
}

func TestParseKiroEventStream_SingleFrame(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{"content": "hello world"})
	frame := buildTestEventFrame(payload)
	events := parseKiroEventStream(frame)
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].content != "hello world" {
		t.Errorf("content: got %q, want %q", events[0].content, "hello world")
	}
}

func TestParseKiroEventStream_MultipleFrames(t *testing.T) {
	p1, _ := json.Marshal(map[string]any{"content": "chunk1"})
	p2, _ := json.Marshal(map[string]any{"content": "chunk2"})
	p3, _ := json.Marshal(map[string]any{"stop": true})
	data := append(append(buildTestEventFrame(p1), buildTestEventFrame(p2)...), buildTestEventFrame(p3)...)
	events := parseKiroEventStream(data)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].content != "chunk1" {
		t.Errorf("event[0]: got %q, want chunk1", events[0].content)
	}
	if !events[2].stop {
		t.Error("expected event[2] to be stop")
	}
}

func TestKiroExecutor_Execute_MockServer(t *testing.T) {
	eventPayload, _ := json.Marshal(map[string]any{"content": "Hello from Kiro!"})
	frame := buildTestEventFrame(eventPayload)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frame)
	}))
	defer srv.Close()

	// Override endpoints to point to mock server.
	origEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: srv.URL, Name: "Mock"}}
	defer func() { kiroEndpoints = origEndpoints }()

	ex := NewKiroExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Metadata: map[string]any{
			"access_token":  "fake-token",
			"refresh_token": "fake-refresh",
			"expires_at":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
	req := cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`),
	}

	resp, err := ex.Execute(context.Background(), auth, req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("Execute: unexpected error: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(resp.Payload, &out); err != nil {
		t.Fatalf("unmarshal response payload: %v", err)
	}
	content, _ := out["content"].([]any)
	if len(content) == 0 {
		t.Fatal("expected content array in response")
	}
	block, _ := content[0].(map[string]any)
	if block["text"] != "Hello from Kiro!" {
		t.Errorf("content text: got %v, want %q", block["text"], "Hello from Kiro!")
	}
}

func TestKiroExecutor_ExecuteStream_MockServer(t *testing.T) {
	p1, _ := json.Marshal(map[string]any{"content": "chunk1"})
	p2, _ := json.Marshal(map[string]any{"content": "chunk2"})
	p3, _ := json.Marshal(map[string]any{"stop": true})
	frames := append(append(buildTestEventFrame(p1), buildTestEventFrame(p2)...), buildTestEventFrame(p3)...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(frames)
	}))
	defer srv.Close()

	origEndpoints := kiroEndpoints
	kiroEndpoints = []kiroEndpoint{{URL: srv.URL, Name: "Mock"}}
	defer func() { kiroEndpoints = origEndpoints }()

	ex := NewKiroExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Metadata: map[string]any{
			"access_token":  "fake-token",
			"refresh_token": "fake-refresh",
			"expires_at":    time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
	req := cliproxyexecutor.Request{
		Model:   "claude-sonnet-4-6",
		Payload: []byte(`{"model":"claude-sonnet-4-6","messages":[{"role":"user","content":"hi"}]}`),
	}

	result, err := ex.ExecuteStream(context.Background(), auth, req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("claude"),
	})
	if err != nil {
		t.Fatalf("ExecuteStream: unexpected error: %v", err)
	}

	var allPayloads []string
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error: %v", chunk.Err)
		}
		allPayloads = append(allPayloads, string(chunk.Payload))
	}

	combined := strings.Join(allPayloads, "")
	if !strings.Contains(combined, "chunk1") {
		t.Errorf("expected 'chunk1' in stream output, got: %q", combined)
	}
	if !strings.Contains(combined, "chunk2") {
		t.Errorf("expected 'chunk2' in stream output, got: %q", combined)
	}
}
