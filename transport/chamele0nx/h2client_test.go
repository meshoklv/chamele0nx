package chamele0nx

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	reqlib "github.com/imroc/req/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestChromeH2Fingerprint reads the raw HTTP/2 connection preface the client
// emits and checks the Chrome fingerprint: SETTINGS entries and their order,
// the initial WINDOW_UPDATE, and the pseudo-header and header order.
func TestChromeH2Fingerprint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		settings []http2.Setting
		flow     uint32
		names    []string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() { done <- r }()
		c, err := ln.Accept()
		if err != nil {
			r.err = err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(http2.ClientPreface))
		if _, r.err = io.ReadFull(c, buf); r.err != nil {
			return
		}
		fr := http2.NewFramer(io.Discard, c)
		for r.names == nil {
			f, err := fr.ReadFrame()
			if err != nil {
				r.err = err
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if f.IsAck() {
					continue
				}
				_ = f.ForeachSetting(func(s http2.Setting) error {
					r.settings = append(r.settings, s)
					return nil
				})
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 && r.flow == 0 {
					r.flow = f.Increment
				}
			case *http2.HeadersFrame:
				dec := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {
					r.names = append(r.names, hf.Name)
				})
				if _, r.err = dec.Write(f.HeaderBlockFragment()); r.err != nil {
					return
				}
			}
		}
	}()

	h2t := newChromeH2Transport(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Scheme: "https", Host: "example.com", Path: "/api"},
		Host:   "example.com",
		Header: http.Header{},
		Body:   io.NopCloser(io.LimitReader(zeroReader{}, 0)),
	}
	req = req.WithContext(ctx)
	req.Header.Set("Cookie", "a=b")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "x")
	req.Header[reqlib.HeaderOderKey] = []string{"cookie", "content-type", "accept", "user-agent"}
	req.Header[reqlib.PseudoHeaderOderKey] = chromePseudoHeaderOrder
	go func() {
		if resp, err := h2t.RoundTrip(req); err == nil {
			_ = resp.Body.Close()
		}
	}()

	r := <-done
	if r.err != nil {
		t.Fatalf("reading preface: %v", r.err)
	}
	wantSettings := []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: 65536},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 6291456},
		{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	}
	if len(r.settings) != len(wantSettings) {
		t.Fatalf("settings = %v, want %v", r.settings, wantSettings)
	}
	for i := range wantSettings {
		if r.settings[i] != wantSettings[i] {
			t.Errorf("setting[%d] = %v, want %v", i, r.settings[i], wantSettings[i])
		}
	}
	if r.flow != 15663105 {
		t.Errorf("connection WINDOW_UPDATE = %d, want 15663105", r.flow)
	}
	want := []string{":method", ":authority", ":scheme", ":path", "cookie", "content-type", "accept", "user-agent"}
	t.Logf("headers: %v", r.names)
	if len(r.names) < len(want) {
		t.Fatalf("header names = %v", r.names)
	}
	for i := range want {
		if r.names[i] != want[i] {
			t.Errorf("header[%d] = %q, want %q (all: %v)", i, r.names[i], want[i], r.names)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, io.EOF }
