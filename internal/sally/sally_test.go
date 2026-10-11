package sally

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPairApprovedAfterPendingAndASlowDown(t *testing.T) {
	var polls int32
	var startBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("pairing must not send a token")
		}
		switch r.URL.Path {
		case "/api/agent/pair/start":
			json.NewDecoder(r.Body).Decode(&startBody)
			json.NewEncoder(w).Encode(map[string]any{
				"deviceCode": "dc-1", "userCode": "WXYZ-1234",
				"verificationUri":         "https://sally.test/connect",
				"verificationUriComplete": "https://sally.test/connect?code=WXYZ-1234",
				"interval":                5, "expiresIn": 600,
			})
		case "/api/agent/pair/poll":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["deviceCode"] != "dc-1" {
				t.Errorf("polled with %q", in["deviceCode"])
			}
			switch atomic.AddInt32(&polls, 1) {
			case 1:
				json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			case 2:
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(429)
			default:
				json.NewEncoder(w).Encode(map[string]any{
					"status": "approved", "token": "tok-9",
					"device":      map[string]any{"id": "dev-1", "approvedCompanyIds": []string{"co-1"}, "capability": "SCAN"},
					"companyName": "Alpha Traders",
				})
			}
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test")
	c.pollEvery = 5 * time.Millisecond
	var shown *PairStartResponse
	p, err := c.Pair(context.Background(), PairStartRequest{DeviceName: "ACCOUNTS-PC", Platform: "windows", AgentVersion: "1.1.0"}, func(s *PairStartResponse) { shown = s })
	if err != nil {
		t.Fatal(err)
	}
	if startBody["capability"] != "SCAN" || startBody["platform"] != "windows" {
		t.Fatalf("start body %v", startBody)
	}
	if shown == nil || shown.VerificationURIComplete != "https://sally.test/connect?code=WXYZ-1234" {
		t.Fatal("the code was not shown")
	}
	if p.Token != "tok-9" || p.CompanyID != "co-1" || p.CompanyName != "Alpha Traders" || p.DeviceID != "dev-1" {
		t.Fatalf("%+v", p)
	}
}

func TestPairDeniedAndNotFound(t *testing.T) {
	for _, status := range []string{"denied", "expired", "not_found", "consumed"} {
		t.Run(status, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/agent/pair/start" {
					json.NewEncoder(w).Encode(map[string]any{"deviceCode": "d", "userCode": "U", "interval": 1, "expiresIn": 60})
					return
				}
				if status == "not_found" {
					w.WriteHeader(404)
				}
				json.NewEncoder(w).Encode(map[string]any{"status": status})
			}))
			defer srv.Close()
			c := NewClient(srv.URL, "test")
			c.pollEvery = time.Millisecond
			_, err := c.Pair(context.Background(), PairStartRequest{}, nil)
			var pe *PairError
			if !errors.As(err, &pe) || pe.Status != status {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestHeartbeatSendsTheDeviceHeadersAndReadsCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("x-active-company-id") != "co-1" {
			w.WriteHeader(401)
			return
		}
		var hb map[string]any
		json.NewDecoder(r.Body).Decode(&hb)
		if hb["agentVersion"] != "1.1.0" {
			t.Errorf("heartbeat %v", hb)
		}
		io.WriteString(w, `{"heartbeatSec":10,"companyName":"Alpha Traders","settings":{"autoStart":false,"startDelaySec":5},
		  "commands":[{"id":"c1","kind":"PAUSE","pauseMinutes":15},{"id":"c2","kind":"PAUSE","pauseMinutes":null},{"id":"c3","kind":"WOBBLE"}],
		  "minAgentVersion":null,"updateManifestUrl":"https://x/print-agent/latest.json"}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	if _, err := c.Heartbeat(context.Background(), HeartbeatRequest{}); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("unpaired heartbeat: %v", err)
	}
	c.SetAuth("tok", "co-1")
	r, err := c.Heartbeat(context.Background(), HeartbeatRequest{AgentVersion: "1.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Settings == nil || r.Settings.AutoStart == nil || *r.Settings.AutoStart || r.Settings.StartDelaySec != 5 {
		t.Fatalf("settings %+v", r.Settings)
	}
	if len(r.Commands) != 3 || *r.Commands[0].PauseMinutes != 15 || r.Commands[1].PauseMinutes != nil {
		t.Fatalf("commands %+v", r.Commands)
	}
}

func TestErrorsAreClassified(t *testing.T) {
	code := 401
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		io.WriteString(w, `{"error":"no","code":"PLAN"}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	c.SetAuth("t", "c")
	_, err := c.Heartbeat(context.Background(), HeartbeatRequest{})
	if !IsUnauthorized(err) || IsForbidden(err) {
		t.Fatalf("401: %v", err)
	}
	code = 403
	_, err = c.Heartbeat(context.Background(), HeartbeatRequest{})
	var ae *APIError
	if !IsForbidden(err) || !errors.As(err, &ae) || ae.Code != "PLAN" {
		t.Fatalf("403: %v", err)
	}
}
