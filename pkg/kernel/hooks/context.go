package hooks

import (
	"time"
)

// HookContext provides metadata for kernel execution hooks
type HookContext struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// NewHookContext initializes a fresh context for a scan execution
func NewHookContext(id string) *HookContext {
	return &HookContext{
		ID:        id,
		Timestamp: time.Now(),
		Metadata:  make(map[string]interface{}),
	}
}