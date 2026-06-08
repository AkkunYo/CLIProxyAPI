package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tiktoken-go/tokenizer"
)

// kiroEndpoint describes one Kiro API endpoint with optional AWS routing header.
type kiroEndpoint struct {
	URL       string
	AmzTarget string
	Name      string
}

// kiroEndpoints lists all Kiro API endpoints tried in order.
// Package-level var so integration tests can override it.
var kiroEndpoints = []kiroEndpoint{
	{
		URL:  "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
		Name: "Kiro IDE",
	},
	{
		URL:       "https://codewhisperer.us-east-1.amazonaws.com/generateAssistantResponse",
		AmzTarget: "AmazonCodeWhispererStreamingService.GenerateAssistantResponse",
		Name:      "CodeWhisperer",
	},
	{
		URL:       "https://q.us-east-1.amazonaws.com/generateAssistantResponse",
		AmzTarget: "AmazonQDeveloperStreamingService.SendMessage",
		Name:      "AmazonQ",
	},
}

// KiroExecutor is a stateless executor for Kiro (AWS Amazon Q / CodeWhisperer).
// It translates Claude-format requests into Kiro's ConversationState protocol and
// parses binary AWS Event Stream responses back to Claude format.
type KiroExecutor struct {
	cfg *config.Config
}

// NewKiroExecutor creates a new Kiro executor.
func NewKiroExecutor(cfg *config.Config) *KiroExecutor {
	return &KiroExecutor{cfg: cfg}
}

// Identifier returns the executor provider key.
func (e *KiroExecutor) Identifier() string { return "kiro" }

// Execute performs a non-streaming request to Kiro and returns a Claude-format response.
func (e *KiroExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	from := opts.SourceFormat
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	key, err := e.resolveKey(ctx, auth)
	if err != nil {
		return resp, err
	}

	body, err := e.buildKiroPayload(from, baseModel, req, opts, false)
	if err != nil {
		return resp, fmt.Errorf("kiro executor: build payload: %w", err)
	}

	machineID := kiroMachineID(key.ProfileArn, key.ClientID)
	httpResp, endpoint, err := e.tryEndpoints(ctx, auth, key, machineID, body)
	if err != nil {
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("kiro executor: close response body: %v", errClose)
		}
	}()

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("kiro executor: error status=%d endpoint=%s body=%s",
			httpResp.StatusCode, endpoint.Name, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		return resp, statusErr{code: httpResp.StatusCode, msg: string(b)}
	}

	rawBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, fmt.Errorf("kiro executor: read response body: %w", err)
	}
	helps.AppendAPIResponseChunk(ctx, e.cfg, rawBody)

	events := parseKiroEventStream(rawBody)
	text, inputTokens, outputTokens := collectKiroEvents(events)
	reporter.Publish(ctx, usage.Detail{InputTokens: int64(inputTokens), OutputTokens: int64(outputTokens)})

	out, err := buildClaudeNonStreamResponse(req.Model, text, inputTokens, outputTokens)
	if err != nil {
		return resp, fmt.Errorf("kiro executor: marshal response: %w", err)
	}

	// Translate back to source format if needed (e.g. openai).
	var param any
	translated := sdktranslator.TranslateNonStream(ctx, sdktranslator.FromString("kiro"), from, req.Model, opts.OriginalRequest, body, out, &param)
	return cliproxyexecutor.Response{Payload: translated, Headers: httpResp.Header.Clone()}, nil
}

// ExecuteStream performs a streaming request to Kiro and returns Claude SSE chunks.
func (e *KiroExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	from := opts.SourceFormat
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	key, err := e.resolveKey(ctx, auth)
	if err != nil {
		return nil, err
	}

	body, err := e.buildKiroPayload(from, baseModel, req, opts, true)
	if err != nil {
		return nil, fmt.Errorf("kiro executor: build payload: %w", err)
	}

	machineID := kiroMachineID(key.ProfileArn, key.ClientID)
	httpResp, endpoint, err := e.tryEndpoints(ctx, auth, key, machineID, body)
	if err != nil {
		return nil, err
	}

	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("kiro executor: close error response body: %v", errClose)
		}
		helps.LogWithRequestID(ctx).Debugf("kiro executor: error status=%d endpoint=%s", httpResp.StatusCode, endpoint.Name)
		return nil, statusErr{code: httpResp.StatusCode, msg: string(b)}
	}

	msgID := "msg_" + uuid.New().String()
	out := make(chan cliproxyexecutor.StreamChunk)

	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("kiro executor: close stream body: %v", errClose)
			}
		}()

		// Emit message_start
		startEvent := buildClaudeStreamStart(msgID, req.Model)
		helps.AppendAPIResponseChunk(ctx, e.cfg, startEvent)
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: startEvent}:
		case <-ctx.Done():
			return
		}
		// content_block_start
		blockStart := buildClaudeContentBlockStart()
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: blockStart}:
		case <-ctx.Done():
			return
		}

		var totalOutput int
		rawBuf := make([]byte, 0, 8192)
		readBuf := make([]byte, 4096)

		for {
			n, readErr := httpResp.Body.Read(readBuf)
			if n > 0 {
				rawBuf = append(rawBuf, readBuf[:n]...)
				events, remaining := parseKiroEventStreamIncremental(rawBuf)
				rawBuf = remaining

				for _, ev := range events {
					if ev.stop {
						continue
					}
					if ev.content == "" {
						continue
					}
					totalOutput += len(ev.content) / 4
					delta := buildClaudeContentDelta(ev.content)
					helps.AppendAPIResponseChunk(ctx, e.cfg, delta)
					select {
					case out <- cliproxyexecutor.StreamChunk{Payload: delta}:
					case <-ctx.Done():
						return
					}
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				helps.RecordAPIResponseError(ctx, e.cfg, readErr)
				reporter.PublishFailure(ctx, readErr)
				select {
				case out <- cliproxyexecutor.StreamChunk{Err: readErr}:
				case <-ctx.Done():
				}
				return
			}
		}

		reporter.Publish(ctx, usage.Detail{OutputTokens: int64(totalOutput)})

		// content_block_stop
		blockStop := buildClaudeContentBlockStop()
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: blockStop}:
		case <-ctx.Done():
			return
		}
		// message_delta (stop_reason)
		msgDelta := buildClaudeMessageDelta(totalOutput)
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: msgDelta}:
		case <-ctx.Done():
			return
		}
		// message_stop
		msgStop := buildClaudeMessageStop()
		select {
		case out <- cliproxyexecutor.StreamChunk{Payload: msgStop}:
		case <-ctx.Done():
		}
	}()

	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

// resolveKey extracts and refreshes the Kiro OAuth key from auth metadata.
func (e *KiroExecutor) resolveKey(ctx context.Context, auth *cliproxyauth.Auth) (*kiroauth.OAuthKey, error) {
	if auth == nil || auth.Metadata == nil {
		return nil, errors.New("kiro executor: auth metadata is nil")
	}
	key := &kiroauth.OAuthKey{
		AccessToken:  kiroMetaStr(auth.Metadata, "access_token"),
		RefreshToken: kiroMetaStr(auth.Metadata, "refresh_token"),
		ExpiresAt:    kiroMetaStr(auth.Metadata, "expires_at"),
		AuthMethod:   kiroMetaStr(auth.Metadata, "auth_method"),
		Region:       kiroMetaStr(auth.Metadata, "region"),
		ClientID:     kiroMetaStr(auth.Metadata, "client_id"),
		ClientSecret: kiroMetaStr(auth.Metadata, "client_secret"),
		IDCRegion:    kiroMetaStr(auth.Metadata, "idc_region"),
		ProfileArn:   kiroMetaStr(auth.Metadata, "profile_arn"),
	}
	if key.IsExpired(30 * time.Second) {
		if strings.TrimSpace(key.RefreshToken) == "" {
			return nil, errors.New("kiro executor: access_token expired and no refresh_token present")
		}
		result, refreshErr := kiroauth.RefreshToken(ctx, key)
		if refreshErr != nil {
			return nil, fmt.Errorf("kiro executor: token refresh: %w", refreshErr)
		}
		key.AccessToken = result.AccessToken
		key.RefreshToken = result.RefreshToken
		key.ExpiresAt = result.ExpiresAt.UTC().Format(time.RFC3339)
		if result.ProfileArn != "" {
			key.ProfileArn = result.ProfileArn
		}
		auth.Metadata["access_token"] = key.AccessToken
		auth.Metadata["refresh_token"] = key.RefreshToken
		auth.Metadata["expires_at"] = key.ExpiresAt
		if key.ProfileArn != "" {
			auth.Metadata["profile_arn"] = key.ProfileArn
		}
	}
	return key, nil
}

// buildKiroPayload translates the inbound Claude/OpenAI payload to Kiro ConversationState JSON.
// It first normalises to OpenAI via the translator layer, then converts to Kiro format.
func (e *KiroExecutor) buildKiroPayload(from sdktranslator.Format, baseModel string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, stream bool) ([]byte, error) {
	toOpenAI := sdktranslator.FromString("openai")

	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := bytes.Clone(originalPayloadSource)
	originalTranslated := sdktranslator.TranslateRequest(from, toOpenAI, baseModel, originalPayload, stream)
	oaiBody := sdktranslator.TranslateRequest(from, toOpenAI, baseModel, bytes.Clone(req.Payload), stream)

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	oaiBody = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, toOpenAI.String(), from.String(), "", oaiBody, originalTranslated, requestedModel, requestPath, opts.Headers)

	return translateOpenAIToKiro(oaiBody, kiroMapModel(baseModel))
}

// tryEndpoints attempts each kiroEndpoint in order, returning the first successful response.
// Retries on 429 and 5xx only.
func (e *KiroExecutor) tryEndpoints(ctx context.Context, auth *cliproxyauth.Auth, key *kiroauth.OAuthKey, machineID string, body []byte) (*http.Response, kiroEndpoint, error) {
	var lastErr error
	for _, ep := range kiroEndpoints {
		httpResp, err := e.doHTTP(ctx, auth, key, ep, machineID, body)
		if err == nil {
			return httpResp, ep, nil
		}
		lastErr = err
		if se, ok := err.(statusErr); ok {
			if se.code != 429 && !(se.code >= 500 && se.code < 600) {
				return nil, ep, err
			}
		}
		log.Warnf("kiro executor: endpoint %s failed: %v — trying next", ep.Name, err)
	}
	return nil, kiroEndpoint{}, fmt.Errorf("kiro executor: all endpoints failed: %w", lastErr)
}

// doHTTP builds and executes a single HTTP request to the given endpoint.
func (e *KiroExecutor) doHTTP(ctx context.Context, auth *cliproxyauth.Auth, key *kiroauth.OAuthKey, ep kiroEndpoint, machineID string, body []byte) (*http.Response, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kiro executor: build request for %s: %w", ep.Name, err)
	}

	applyKiroHeaders(httpReq, key.AccessToken, machineID, ep.AmzTarget)

	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       ep.URL,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      body,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	if resp.StatusCode == 429 || resp.StatusCode >= 500 {
		b, _ := io.ReadAll(resp.Body)
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("kiro executor: close error body: %v", errClose)
		}
		return nil, statusErr{code: resp.StatusCode, msg: string(b)}
	}
	return resp, nil
}

// --- Payload translation (OpenAI → Kiro ConversationState) ---

type kiroRequest struct {
	ConversationState kiroConvState  `json:"conversationState"`
	ProfileArn        string         `json:"profileArn,omitempty"`
	InferenceConfig   *kiroInfConfig `json:"inferenceConfig,omitempty"`
}

type kiroConvState struct {
	AgentContinuationID string          `json:"agentContinuationId"`
	AgentTaskType       string          `json:"agentTaskType"`
	ChatTriggerType     string          `json:"chatTriggerType"`
	ConversationID      string          `json:"conversationId"`
	CurrentMessage      kiroCurrentMsg  `json:"currentMessage"`
	History             []kiroHistEntry `json:"history,omitempty"`
}

type kiroCurrentMsg struct {
	UserInputMessage kiroUserMsg `json:"userInputMessage"`
}

type kiroUserMsg struct {
	Content                 string          `json:"content"`
	ModelID                 string          `json:"modelId"`
	Origin                  string          `json:"origin"`
	UserInputMessageContext *kiroMsgContext `json:"userInputMessageContext,omitempty"`
}

type kiroMsgContext struct {
	Tools       []kiroToolWrapper `json:"tools,omitempty"`
	ToolResults []kiroToolResult  `json:"toolResults,omitempty"`
}

type kiroToolWrapper struct {
	ToolSpecification kiroToolSpec `json:"toolSpecification"`
}

type kiroToolSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema struct {
		JSON interface{} `json:"json"`
	} `json:"inputSchema"`
}

type kiroToolResult struct {
	ToolUseID string              `json:"toolUseId"`
	Content   []kiroResultContent `json:"content"`
	Status    string              `json:"status"`
}

type kiroResultContent struct {
	Text string `json:"text"`
}

type kiroHistEntry struct {
	UserInputMessage         *kiroUserMsg      `json:"userInputMessage,omitempty"`
	AssistantResponseMessage *kiroAssistantMsg `json:"assistantResponseMessage,omitempty"`
}

type kiroAssistantMsg struct {
	Content  string        `json:"content"`
	ToolUses []kiroToolUse `json:"toolUses,omitempty"`
}

type kiroToolUse struct {
	ToolUseID string                 `json:"toolUseId"`
	Name      string                 `json:"name"`
	Input     map[string]interface{} `json:"input"`
}

type kiroInfConfig struct {
	MaxTokens   int     `json:"maxTokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	TopP        float64 `json:"topP,omitempty"`
}

// translateOpenAIToKiro converts an OpenAI-format JSON payload to Kiro's ConversationState.
// It handles system prompts, multi-turn history, tool calls, and tool results.
func translateOpenAIToKiro(oaiPayload []byte, modelID string) ([]byte, error) {
	parsed := gjson.ParseBytes(oaiPayload)
	messages := parsed.Get("messages").Array()

	var systemPrompt string
	history := make([]kiroHistEntry, 0)
	var currentContent string
	var currentToolResults []kiroToolResult

	// Extract tools from request.
	var msgContext *kiroMsgContext
	tools := parsed.Get("tools")
	if tools.Exists() && tools.IsArray() {
		ktools := make([]kiroToolWrapper, 0)
		tools.ForEach(func(_, t gjson.Result) bool {
			fn := t.Get("function")
			name := fn.Get("name").String()
			desc := fn.Get("description").String()
			var schema interface{}
			if s := fn.Get("parameters"); s.Exists() {
				_ = json.Unmarshal([]byte(s.Raw), &schema)
			}
			tw := kiroToolWrapper{}
			tw.ToolSpecification.Name = name
			tw.ToolSpecification.Description = desc
			tw.ToolSpecification.InputSchema.JSON = schema
			ktools = append(ktools, tw)
			return true
		})
		if len(ktools) > 0 {
			msgContext = &kiroMsgContext{Tools: ktools}
		}
	}

	start := 0
	if len(messages) > 0 && messages[0].Get("role").String() == "system" {
		systemPrompt = kiroExtractText(messages[0])
		start = 1
	}

	for i := start; i < len(messages); i++ {
		msg := messages[i]
		role := msg.Get("role").String()
		isLast := i == len(messages)-1

		switch role {
		case "user":
			content := msg.Get("content")
			textContent := ""
			var toolResults []kiroToolResult

			if content.Type == gjson.String {
				textContent = strings.TrimSpace(content.String())
			} else if content.IsArray() {
				var textParts []string
				content.ForEach(func(_, item gjson.Result) bool {
					switch item.Get("type").String() {
					case "text":
						textParts = append(textParts, item.Get("text").String())
					case "tool_result":
						tr := kiroToolResult{
							ToolUseID: item.Get("tool_use_id").String(),
							Status:    "success",
						}
						contentArr := item.Get("content")
						if contentArr.Type == gjson.String {
							tr.Content = []kiroResultContent{{Text: contentArr.String()}}
						} else if contentArr.IsArray() {
							contentArr.ForEach(func(_, c gjson.Result) bool {
								if c.Get("type").String() == "text" {
									tr.Content = append(tr.Content, kiroResultContent{Text: c.Get("text").String()})
								}
								return true
							})
						}
						toolResults = append(toolResults, tr)
					}
					return true
				})
				textContent = strings.TrimSpace(strings.Join(textParts, "\n"))
			}

			if isLast {
				currentContent = textContent
				currentToolResults = toolResults
			} else {
				histEntry := kiroHistEntry{
					UserInputMessage: &kiroUserMsg{
						Content: textContent,
						ModelID: modelID,
						Origin:  "AI_EDITOR",
					},
				}
				if len(toolResults) > 0 {
					histEntry.UserInputMessage.UserInputMessageContext = &kiroMsgContext{
						ToolResults: toolResults,
					}
				}
				history = append(history, histEntry)
			}

		case "assistant":
			content := msg.Get("content")
			var textParts []string
			var toolUses []kiroToolUse

			if content.Type == gjson.String {
				textParts = append(textParts, content.String())
			} else if content.IsArray() {
				content.ForEach(func(_, item gjson.Result) bool {
					switch item.Get("type").String() {
					case "text":
						textParts = append(textParts, item.Get("text").String())
					case "tool_use":
						tu := kiroToolUse{
							ToolUseID: item.Get("id").String(),
							Name:      item.Get("name").String(),
						}
						var inp map[string]interface{}
						if inputRaw := item.Get("input"); inputRaw.Exists() {
							_ = json.Unmarshal([]byte(inputRaw.Raw), &inp)
						}
						tu.Input = inp
						toolUses = append(toolUses, tu)
					}
					return true
				})
			} else {
				// tool_calls in OpenAI format
				toolCalls := msg.Get("tool_calls")
				if toolCalls.IsArray() {
					toolCalls.ForEach(func(_, tc gjson.Result) bool {
						tu := kiroToolUse{
							ToolUseID: tc.Get("id").String(),
							Name:      tc.Get("function.name").String(),
						}
						var inp map[string]interface{}
						if argsRaw := tc.Get("function.arguments"); argsRaw.Exists() {
							_ = json.Unmarshal([]byte(argsRaw.String()), &inp)
						}
						tu.Input = inp
						toolUses = append(toolUses, tu)
						return true
					})
				}
				if c := msg.Get("content"); c.Type == gjson.String {
					textParts = append(textParts, c.String())
				}
			}

			history = append(history, kiroHistEntry{
				AssistantResponseMessage: &kiroAssistantMsg{
					Content:  strings.TrimSpace(strings.Join(textParts, "\n")),
					ToolUses: toolUses,
				},
			})
		}
	}

	// Build final content string (inject system prompt as header).
	finalContent := ""
	if systemPrompt != "" {
		finalContent = "--- SYSTEM PROMPT ---\n" + systemPrompt + "\n--- END SYSTEM PROMPT ---\n\n"
	}
	if currentContent != "" {
		finalContent += currentContent
	} else {
		finalContent = "."
	}

	// Stable conversation ID derived from model + system + first user turn.
	anchor := modelID + "|" + systemPrompt + "|" + currentContent
	hash := sha256.Sum256([]byte(anchor))
	convID := hex.EncodeToString(hash[:])

	// Attach tool results and tools to current message context.
	if len(currentToolResults) > 0 {
		if msgContext == nil {
			msgContext = &kiroMsgContext{}
		}
		msgContext.ToolResults = currentToolResults
	}

	payload := kiroRequest{
		ConversationState: kiroConvState{
			AgentContinuationID: uuid.New().String(),
			AgentTaskType:       "vibe",
			ChatTriggerType:     "MANUAL",
			ConversationID:      convID,
			CurrentMessage: kiroCurrentMsg{
				UserInputMessage: kiroUserMsg{
					Content:                 finalContent,
					ModelID:                 modelID,
					Origin:                  "AI_EDITOR",
					UserInputMessageContext: msgContext,
				},
			},
			History: history,
		},
		InferenceConfig: &kiroInfConfig{MaxTokens: 4096},
	}

	if mt := parsed.Get("max_tokens"); mt.Exists() && mt.Int() > 0 {
		payload.InferenceConfig.MaxTokens = int(mt.Int())
	}
	if t := parsed.Get("temperature"); t.Exists() {
		payload.InferenceConfig.Temperature = t.Float()
	}
	if tp := parsed.Get("top_p"); tp.Exists() {
		payload.InferenceConfig.TopP = tp.Float()
	}

	return json.Marshal(payload)
}

// kiroExtractText extracts plain text from a gjson message result.
func kiroExtractText(msg gjson.Result) string {
	content := msg.Get("content")
	if content.Type == gjson.String {
		return strings.TrimSpace(content.String())
	}
	var parts []string
	content.ForEach(func(_, item gjson.Result) bool {
		if item.Get("type").String() == "text" {
			parts = append(parts, item.Get("text").String())
		}
		return true
	})
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// kiroMapModel maps common Claude model aliases to Kiro model IDs.
func kiroMapModel(model string) string {
	lower := strings.ToLower(model)
	mapping := map[string]string{
		"claude-sonnet-4-6":          "claude-sonnet-4.6",
		"claude-sonnet-4.6":          "claude-sonnet-4.6",
		"claude-opus-4-7":            "claude-opus-4.7",
		"claude-opus-4.7":            "claude-opus-4.7",
		"claude-opus-4-6":            "claude-opus-4.6",
		"claude-opus-4.6":            "claude-opus-4.6",
		"claude-haiku-4-5":           "claude-haiku-4.5",
		"claude-haiku-4.5":           "claude-haiku-4.5",
		"claude-sonnet-4-5":          "claude-sonnet-4.5",
		"claude-sonnet-4.5":          "claude-sonnet-4.5",
		"claude-opus-4-5":            "claude-opus-4.5",
		"claude-opus-4.5":            "claude-opus-4.5",
		"claude-3-7-sonnet-20250219": "claude-3-7-sonnet-20250219",
	}
	for k, v := range mapping {
		if strings.Contains(lower, k) {
			return v
		}
	}
	return "claude-sonnet-4.5"
}

// kiroMachineID generates the x-amzn-codewhisperer-machine-id from profileArn and clientID.
// applyKiroHeaders sets the required AWS/Kiro headers on req.
// amzTarget may be empty for the Kiro IDE endpoint.
func applyKiroHeaders(req *http.Request, accessToken, machineID, amzTarget string) {
	invocationID := uuid.New().String()
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", fmt.Sprintf(
		"aws-sdk-js/1.0.34 ua/2.1 os/darwin lang/js md/nodejs#20.0.0 api/codewhispererstreaming#1.0.34 m/E KiroIDE-0.11.63-%s",
		machineID,
	))
	req.Header.Set("x-amz-user-agent", fmt.Sprintf("aws-sdk-js/1.0.34 KiroIDE-0.11.63-%s", machineID))
	req.Header.Set("Amz-Sdk-Invocation-Id", invocationID)
	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
	req.Header.Set("x-amzn-kiro-agent-mode", "vibe")
	req.Header.Set("x-amzn-codewhisperer-optout", "true")
	req.Header.Set("x-amzn-codewhisperer-machine-id", machineID)
	if amzTarget != "" {
		req.Header.Set("X-Amz-Target", amzTarget)
	}
}

func kiroMachineID(profileArn, clientID string) string {
	h := sha256.Sum256([]byte(profileArn + "|" + clientID))
	return hex.EncodeToString(h[:16])
}

// --- AWS Event Stream parser ---

type kiroEvent struct {
	content string
	name    string
	stop    bool
}

// parseKiroEventStream parses a complete AWS Event Stream binary buffer.
func parseKiroEventStream(data []byte) []kiroEvent {
	events, _ := parseKiroEventStreamIncremental(data)
	return events
}

// parseKiroEventStreamIncremental parses as many complete frames as possible from buf,
// returning events and the unconsumed remainder.
func parseKiroEventStreamIncremental(buf []byte) ([]kiroEvent, []byte) {
	data := buf
	events := make([]kiroEvent, 0)
	offset := 0

	for offset < len(data) {
		if offset+12 > len(data) {
			break
		}
		totalLen := int(binary.BigEndian.Uint32(data[offset:]))
		if totalLen < 16 || offset+totalLen > len(data) {
			// Frame not complete yet.
			break
		}
		headersLen := int(binary.BigEndian.Uint32(data[offset+4:]))
		payloadStart := offset + 12 + headersLen
		payloadEnd := offset + totalLen - 4

		if payloadStart > payloadEnd || payloadStart < 0 || payloadEnd > len(data) {
			offset += totalLen
			continue
		}

		payload := data[payloadStart:payloadEnd]
		if len(payload) > 0 {
			var ev struct {
				Content string `json:"content"`
				Name    string `json:"name"`
				Stop    bool   `json:"stop"`
			}
			if err := json.Unmarshal(payload, &ev); err == nil {
				if ev.Content != "" || ev.Name != "" || ev.Stop {
					events = append(events, kiroEvent{content: ev.Content, name: ev.Name, stop: ev.Stop})
				}
			}
		}
		offset += totalLen
	}

	remaining := []byte(nil)
	if offset < len(data) {
		remaining = data[offset:]
	}
	return events, remaining
}

// collectKiroEvents concatenates content from all events and estimates token counts.
func collectKiroEvents(events []kiroEvent) (text string, inputTokens, outputTokens int) {
	var sb strings.Builder
	for _, ev := range events {
		if !ev.stop && ev.content != "" {
			sb.WriteString(ev.content)
		}
	}
	text = sb.String()
	outputTokens = len(text) / 4
	return text, 0, outputTokens
}

// --- Claude response builders ---

func buildClaudeNonStreamResponse(model, text string, inputTokens, outputTokens int) ([]byte, error) {
	resp := map[string]any{
		"id":            "msg_" + uuid.New().String(),
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"usage": map[string]any{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	}
	return json.Marshal(resp)
}

func buildClaudeStreamStart(msgID, model string) []byte {
	ev := map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            msgID,
			"type":          "message",
			"role":          "assistant",
			"content":       []any{},
			"model":         model,
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage":         map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

func buildClaudeContentBlockStart() []byte {
	ev := map[string]any{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]any{
			"type": "text",
			"text": "",
		},
	}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

func buildClaudeContentDelta(text string) []byte {
	ev := map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{
			"type": "text_delta",
			"text": text,
		},
	}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

func buildClaudeContentBlockStop() []byte {
	ev := map[string]any{"type": "content_block_stop", "index": 0}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

func buildClaudeMessageDelta(outputTokens int) []byte {
	ev := map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": outputTokens},
	}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

func buildClaudeMessageStop() []byte {
	ev := map[string]any{"type": "message_stop"}
	b, _ := json.Marshal(ev)
	return []byte("data: " + string(b) + "\n\n")
}

// kiroMetaStr extracts a trimmed string value from a metadata map.
func kiroMetaStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(v)
}

// Refresh refreshes Kiro OAuth credentials using the stored refresh token.
func (e *KiroExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	_, err := e.resolveKey(ctx, auth)
	if err != nil {
		return nil, err
	}
	return auth, nil
}

// HttpRequest injects Kiro credentials into req and executes it.
func (e *KiroExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("kiro executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	key, err := e.resolveKey(ctx, auth)
	if err != nil {
		return nil, err
	}
	machineID := kiroMachineID(key.ProfileArn, key.ClientID)
	applyKiroHeaders(httpReq, key.AccessToken, machineID, "")
	httpClient := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

// CountTokens estimates token count for a Kiro request using a local tokenizer.
func (e *KiroExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	from := opts.SourceFormat
	toOpenAI := sdktranslator.FromString("openai")
	body := sdktranslator.TranslateRequest(from, toOpenAI, req.Model, req.Payload, false)

	enc, err := tokenizer.Get(tokenizer.Cl100kBase)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("kiro executor: tokenizer init failed: %w", err)
	}
	count, err := enc.Count(string(body))
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("kiro executor: token counting failed: %w", err)
	}
	usageJSON := fmt.Sprintf(`{"response":{"usage":{"input_tokens":%d,"output_tokens":0,"total_tokens":%d}}}`, count, count)
	translated := sdktranslator.TranslateTokenCount(ctx, sdktranslator.FromString("kiro"), from, int64(count), []byte(usageJSON))
	return cliproxyexecutor.Response{Payload: translated}, nil
}
