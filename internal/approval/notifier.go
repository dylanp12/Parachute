package approval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier sends notifications about pending approvals
type Notifier struct {
	webhooks []WebhookConfig
	client   *http.Client
}

// NewNotifier creates a notifier with the given webhook configs
func NewNotifier(webhooks []WebhookConfig) *Notifier {
	return &Notifier{
		webhooks: webhooks,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// NotifyPending sends a notification about a pending command
func (n *Notifier) NotifyPending(pc *PendingCommand) error {
	if len(n.webhooks) == 0 {
		return nil
	}

	payload := map[string]any{
		"type":       "pending_approval",
		"id":         pc.ID,
		"command":    pc.Command,
		"tool_name":  pc.ToolName,
		"reason":     pc.Reason,
		"created_at": pc.CreatedAt.Format(time.RFC3339),
		"expires_at": pc.ExpiresAt.Format(time.RFC3339),
		"message":    fmt.Sprintf("🚨 Command requires approval: `%s`", pc.Command),
	}

	var lastErr error
	for _, wh := range n.webhooks {
		if err := n.sendWebhook(wh, payload); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// NotifyDecision sends a notification about an approval decision
func (n *Notifier) NotifyDecision(id string, approved bool) error {
	if len(n.webhooks) == 0 {
		return nil
	}

	decision := "denied"
	emoji := "❌"
	if approved {
		decision = "approved"
		emoji = "✅"
	}

	payload := map[string]any{
		"type":     "decision",
		"id":       id,
		"decision": decision,
		"message":  fmt.Sprintf("%s Command %s: %s", emoji, decision, id),
	}

	var lastErr error
	for _, wh := range n.webhooks {
		if err := n.sendWebhook(wh, payload); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

func (n *Notifier) sendWebhook(wh WebhookConfig, payload map[string]any) error {
	if isDiscordWebhook(wh.URL) {
		payload = wrapForDiscord(payload)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	method := wh.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, wh.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range wh.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func isDiscordWebhook(url string) bool {
	return len(url) > 30 && url[:30] == "https://discord.com/api/webhoo"
}

func wrapForDiscord(payload map[string]any) map[string]any {
	message, _ := payload["message"].(string)
	return map[string]any{
		"content": message,
		"embeds": []map[string]any{{
			"title":       "Parachute Alert",
			"description": fmt.Sprintf("**Command:** `%v`\n**ID:** %v", payload["command"], payload["id"]),
			"color":       16744256,
			"fields":      []map[string]any{{"name": "Reason", "value": payload["reason"], "inline": true}},
		}},
	}
}
