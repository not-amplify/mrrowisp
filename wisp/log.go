package wisp

import (
	"encoding/json"
	"log"
	"time"
)

// logEvent emits a single-line JSON record on stderr. The output is
// fail2ban-friendly: each line is a flat JSON object with stable keys
// "ts" (RFC3339) and "event", plus the caller-supplied fields.
func logEvent(event string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	fields["ts"] = time.Now().UTC().Format(time.RFC3339)
	fields["event"] = event
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	log.Println(string(b))
}
