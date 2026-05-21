package pia

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServerListTestClient builds a PIAClient pointed at the given test server URL.
func newServerListTestClient(serverURL string) *PIAClient {
	return &PIAClient{serverListURL: serverURL}
}

// minimalServerListJSON is a minimal but valid PIA server-list JSON body.
const minimalServerListJSON = `{"regions":[{"id":"us-east","name":"US East","country":"US","auto_region":false,"dns":"us-east.privacy.network","port_forward":false,"geo":false,"servers":{"wg":[{"cn":"us-east.wg.privateinternetaccess.com","ip":"1.2.3.4"}]}}]}`

func TestGetServerList_Success(t *testing.T) {
	// PIA's real response appends a newline and a base64 blob after the closing brace.
	body := minimalServerListJSON + "\nSVZWR09iamVjdEV4dHJhRGF0YQo="
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	list, err := newServerListTestClient(srv.URL).getServerList()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(list.Regions) != 1 {
		t.Errorf("expected 1 region, got %d", len(list.Regions))
	}
	if list.Regions[0].ID != "us-east" {
		t.Errorf("expected region id %q, got %q", "us-east", list.Regions[0].ID)
	}
}

func TestGetServerList_NoJSONBrace(t *testing.T) {
	// Response contains no '}' — getServerList must return an error rather than
	// panicking on a negative slice index.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "this is not json at all")
	}))
	defer srv.Close()

	_, err := newServerListTestClient(srv.URL).getServerList()
	if err == nil {
		t.Fatal("expected error when response has no '}', got nil")
	}
	if !strings.Contains(err.Error(), "no JSON object") {
		t.Errorf("expected 'no JSON object' in error, got: %v", err)
	}
}

func TestGetServerList_InvalidJSON(t *testing.T) {
	// Response has a '}' but the JSON is still invalid.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{ bad json }")
	}))
	defer srv.Close()

	_, err := newServerListTestClient(srv.URL).getServerList()
	if err == nil {
		t.Fatal("expected JSON parse error, got nil")
	}
}

func TestGetServerList_ResponseExceedsLimit(t *testing.T) {
	// A response larger than 1 MiB is truncated by LimitReader. If the 1 MiB
	// window contains a '}', parsing must still succeed. Here we place a valid
	// JSON object well within the limit, followed by a long padding sequence.
	padding := strings.Repeat("X", 2<<20) // 2 MiB of garbage after the JSON
	body := minimalServerListJSON + "\n" + padding
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	// The JSON fits within the 1 MiB cap so parsing should succeed.
	list, err := newServerListTestClient(srv.URL).getServerList()
	if err != nil {
		t.Fatalf("unexpected error with oversized response: %v", err)
	}
	if len(list.Regions) != 1 {
		t.Errorf("expected 1 region, got %d", len(list.Regions))
	}
}

func TestGetServerList_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write nothing — empty body.
	}))
	defer srv.Close()

	_, err := newServerListTestClient(srv.URL).getServerList()
	if err == nil {
		t.Fatal("expected error for empty response, got nil")
	}
}
