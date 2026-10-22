// In-process log buffer for the gomobile facade.
//
// Why this exists: on iOS 17+ there is no working CLI path to read a
// device's unified-log output for a third-party app — `idevicesyslog`
// (libimobiledevice) lost its usbmux pipe in CoreDevice, `log stream`
// has no `--device` flag, and `xcrun devicectl` exposes no log
// subcommand. So when something goes wrong inside the Go side of the
// Chamele0nX stack on a real iPhone, the operator has no way to see it
// unless we collect the logs ourselves and hand them up through the
// gomobile bridge.
//
// Strategy: install a slog.Handler that mirrors every record into a
// fixed-size ring buffer, in addition to the normal stderr text
// handler. The wrapper exposes:
//
//   * Client.RecentLogs()  — full ring buffer as one newline-joined
//                            string, ready to render in a Swift TextEditor
//   * Client.Status() now also embeds the most recent ERROR/WARN line
//     as `last_error`, so a 1 Hz status poll surfaces the latest
//     classified failure without a separate UI refresh path.
//
// Buffer is process-global (slog.SetDefault) — fine for a single Client
// per process, which is the only mode this wrapper supports today.

package mobile

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

const (
	// logBufferSize bounds memory usage on the device. 200 records is
	// enough to capture the full lifecycle of a few reconnect cycles
	// (each cycle emits ~3-5 records: connecting, error, backoff).
	logBufferSize = 200
)

// logRingBuffer is a thread-safe circular buffer of formatted log
// records. New records overwrite the oldest when full.
type logRingBuffer struct {
	mu      sync.Mutex
	records []logRecord
	next    int
	count   int
}

type logRecord struct {
	when  time.Time
	level slog.Level
	msg   string
	// attrs is the formatted "k=v k=v" tail. We pre-render it under
	// the slog handler so the read path doesn't have to walk groups.
	attrs string
}

func newLogRingBuffer(size int) *logRingBuffer {
	return &logRingBuffer{records: make([]logRecord, size)}
}

func (b *logRingBuffer) add(r logRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.records[b.next] = r
	b.next = (b.next + 1) % len(b.records)
	if b.count < len(b.records) {
		b.count++
	}
}

// snapshot returns the records in chronological order (oldest first).
func (b *logRingBuffer) snapshot() []logRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]logRecord, 0, b.count)
	if b.count < len(b.records) {
		// Buffer not yet wrapped: records[0..count) are in order.
		out = append(out, b.records[:b.count]...)
		return out
	}
	// Buffer wrapped: oldest is at next, then wraps around.
	out = append(out, b.records[b.next:]...)
	out = append(out, b.records[:b.next]...)
	return out
}

// lastErrorOrWarn returns the most recent record at level >= WARN,
// formatted as "LEVEL msg attrs". Returns "" if there is no such record.
// Used by Client.Status() to surface a single human-readable error
// string without forcing the Swift caller to parse the whole buffer.
func (b *logRingBuffer) lastErrorOrWarn() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Walk backward through the ring from the most recent record.
	for i := 0; i < b.count; i++ {
		idx := (b.next - 1 - i + len(b.records)) % len(b.records)
		r := b.records[idx]
		if r.level >= slog.LevelWarn {
			return formatRecord(r)
		}
	}
	return ""
}

func formatRecord(r logRecord) string {
	stamp := r.when.Format("15:04:05")
	if r.attrs == "" {
		return fmt.Sprintf("%s %s %s", stamp, r.level.String(), r.msg)
	}
	return fmt.Sprintf("%s %s %s %s", stamp, r.level.String(), r.msg, r.attrs)
}

// joinAll renders the whole buffer as one newline-joined string,
// chronological order. Trailing newline omitted.
func (b *logRingBuffer) joinAll() string {
	recs := b.snapshot()
	if len(recs) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, r := range recs {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(formatRecord(r))
	}
	return sb.String()
}

// ringHandler is a slog.Handler that writes every record into a
// logRingBuffer. It does not write to any io.Writer — the wrapper pairs
// it with slog's text handler if console output is also wanted (it
// isn't on iOS, so we don't bother).
type ringHandler struct {
	buf   *logRingBuffer
	level slog.Level
	attrs []slog.Attr
	group string
}

func newRingHandler(buf *logRingBuffer) *ringHandler {
	return &ringHandler{buf: buf, level: slog.LevelInfo}
}

// Enabled keeps debug records out of the buffer.
//
// The buffer is handed to the host application through RecentLogs, which
// may put it on a screen, save it, or attach it to a crash report. Debug
// records are the ones that carry addresses and names, so the default
// threshold is Info and a caller has to ask for anything lower.
func (h *ringHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *ringHandler) Handle(_ context.Context, r slog.Record) error {
	var sb bytes.Buffer
	first := true
	emit := func(a slog.Attr) bool {
		if !first {
			sb.WriteByte(' ')
		}
		first = false
		sb.WriteString(a.Key)
		sb.WriteByte('=')
		sb.WriteString(a.Value.String())
		return true
	}
	for _, a := range h.attrs {
		emit(a)
	}
	r.Attrs(func(a slog.Attr) bool { return emit(a) })

	h.buf.add(logRecord{
		when:  r.Time,
		level: r.Level,
		msg:   r.Message,
		attrs: sb.String(),
	})
	return nil
}

func (h *ringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	return &ringHandler{buf: h.buf, level: h.level, attrs: combined, group: h.group}
}

func (h *ringHandler) WithGroup(name string) slog.Handler {
	return &ringHandler{buf: h.buf, level: h.level, attrs: h.attrs, group: name}
}

// installLogBuffer creates a fresh ring buffer, swaps it in as the
// default slog logger, and returns a handle the wrapper uses to read
// it back. Process-global by design — see file header.
//
// Safe to call multiple times; each call replaces the buffer of the
// previous one. Calls from different goroutines must be serialised by
// the caller (Client.mu does this in practice).
func installLogBuffer() *logRingBuffer {
	buf := newLogRingBuffer(logBufferSize)
	slog.SetDefault(slog.New(newRingHandler(buf)))
	return buf
}
