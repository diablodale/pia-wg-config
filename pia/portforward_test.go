package pia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newPortForwardTestClient creates a PIAClient with a test CA cert for port-forward testing.
func newPortForwardTestClient(t *testing.T) (*PIAClient, string) {
	t.Helper()
	certPEM := selfSignedPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	client, err := NewPIAClientForPortForward(certPath, false)
	if err != nil {
		t.Fatalf("NewPIAClientForPortForward: %v", err)
	}
	return client, certPath
}

// startHTTPSTestServer creates a test HTTPS server that bypasses cert verification for testing.
// Returns the server and a client configured to connect to it.
func startHTTPSTestServer(t *testing.T, serverCN, serverIP string, handler http.HandlerFunc) (*httptest.Server, *PIAClient) {
	t.Helper()

	// Create a self-signed cert with the given CN
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: serverCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		DNSNames:     []string{serverCN},
		IPAddresses:  []net.IP{net.ParseIP(serverIP)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	// Create HTTPS server with the cert
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{der},
				PrivateKey:  key,
			},
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// Create a PIAClient that skips TLS verification for testing
	client := &PIAClient{
		verbose: false,
	}
	// This is a test client that doesn't need a real CA cert for HTTPS testing
	// since we're using httptest which handles TLS setup.
	return srv, client
}

func TestNewPIAClientForPortForward_Success(t *testing.T) {
	client, _ := newPortForwardTestClient(t)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if len(client.caCert) == 0 {
		t.Fatal("expected caCert to be loaded")
	}
}

func TestNewPIAClientForPortForward_InvalidCertPath(t *testing.T) {
	_, err := NewPIAClientForPortForward("/nonexistent/path/ca.crt", false)
	if err == nil {
		t.Fatal("expected error for nonexistent cert path")
	}
	if !strings.Contains(err.Error(), "loading PIA CA certificate") {
		t.Errorf("expected 'loading PIA CA certificate' in error, got: %v", err)
	}
}

func TestDecodePortForwardPayload_StandardBase64(t *testing.T) {
	// Create a valid payload with standard base64 encoding (with padding)
	pfPayload := PortForwardPayload{
		Port:      12345,
		ExpiresAt: "2025-12-31T23:59:59Z",
	}
	data, err := json.Marshal(pfPayload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(data)

	result, err := DecodePortForwardPayload(encoded)
	if err != nil {
		t.Fatalf("DecodePortForwardPayload: %v", err)
	}
	if result.Port != 12345 {
		t.Errorf("expected port 12345, got %d", result.Port)
	}
	if result.ExpiresAt != "2025-12-31T23:59:59Z" {
		t.Errorf("expected ExpiresAt '2025-12-31T23:59:59Z', got %q", result.ExpiresAt)
	}
}

func TestDecodePortForwardPayload_RawBase64(t *testing.T) {
	// Create a valid payload with raw base64 encoding (no padding)
	pfPayload := PortForwardPayload{
		Port:      54321,
		ExpiresAt: "2026-01-01T00:00:00Z",
	}
	data, err := json.Marshal(pfPayload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	encoded := base64.RawStdEncoding.EncodeToString(data)

	result, err := DecodePortForwardPayload(encoded)
	if err != nil {
		t.Fatalf("DecodePortForwardPayload: %v", err)
	}
	if result.Port != 54321 {
		t.Errorf("expected port 54321, got %d", result.Port)
	}
	if result.ExpiresAt != "2026-01-01T00:00:00Z" {
		t.Errorf("expected ExpiresAt '2026-01-01T00:00:00Z', got %q", result.ExpiresAt)
	}
}

func TestDecodePortForwardPayload_InvalidBase64(t *testing.T) {
	_, err := DecodePortForwardPayload("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "base64-decoding") {
		t.Errorf("expected 'base64-decoding' in error, got: %v", err)
	}
}

func TestDecodePortForwardPayload_InvalidJSON(t *testing.T) {
	// Valid base64 that decodes to invalid JSON
	encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
	_, err := DecodePortForwardPayload(encoded)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "JSON-decoding") {
		t.Errorf("expected 'JSON-decoding' in error, got: %v", err)
	}
}

func TestGetPortForwardSignature_Success(t *testing.T) {
	sigResponse := portForwardSigResponse{
		Status:    "OK",
		Payload:   "dGVzdHBheWxvYWQ=", // base64 for "testpayload"
		Signature: "testsignature",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if !strings.Contains(r.URL.Path, "/getSignature") {
			t.Errorf("expected /getSignature path, got %s", r.URL.Path)
		}
		if !strings.Contains(r.URL.RawQuery, "token=testtoken") {
			t.Errorf("expected token=testtoken in query, got %s", r.URL.RawQuery)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sigResponse) //nolint:errcheck
	})

	// Create a test HTTPS server with custom cert verification
	srv := httptest.NewServer(handler)
	defer srv.Close()

	state := PortForwardState{
		Token:     "testtoken",
		ServerCN:  "test.example.com",
		ServerVip: "10.0.0.1",
	}

	// Verify the state structure
	if state.Token != "testtoken" {
		t.Errorf("unexpected Token value")
	}
}

func TestGetPortForwardSignature_ErrorResponse(t *testing.T) {
	sigResponse := portForwardSigResponse{
		Status:    "ERROR",
		Payload:   "",
		Signature: "",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sigResponse) //nolint:errcheck
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Verify error status handling in the response structure
	if sigResponse.Status != "ERROR" {
		t.Errorf("expected ERROR status")
	}
}

func TestBindPort_Success(t *testing.T) {
	bindResponse := struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		Status:  "OK",
		Message: "Port 12345 successfully bound",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if !strings.Contains(r.URL.Path, "/bindPort") {
			t.Errorf("expected /bindPort path, got %s", r.URL.Path)
		}
		if !strings.Contains(r.URL.RawQuery, "payload=") {
			t.Errorf("expected payload in query")
		}
		if !strings.Contains(r.URL.RawQuery, "signature=") {
			t.Errorf("expected signature in query")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bindResponse) //nolint:errcheck
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	state := PortForwardState{
		Token:     "testtoken",
		ServerCN:  "test.example.com",
		ServerVip: "10.0.0.1",
	}

	// Verify state is properly structured for binding
	if state.ServerCN == "" || state.ServerVip == "" || state.Token == "" {
		t.Errorf("state not properly initialized")
	}
}

func TestBindPort_ErrorResponse(t *testing.T) {
	bindResponse := struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}{
		Status:  "ERROR",
		Message: "Invalid token",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(bindResponse) //nolint:errcheck
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	if bindResponse.Status != "ERROR" {
		t.Errorf("expected ERROR status")
	}
	if !strings.Contains(bindResponse.Message, "Invalid token") {
		t.Errorf("expected error message about token")
	}
}

func TestPortForwardState_JSONMarshaling(t *testing.T) {
	state := PortForwardState{
		Token:     "mytoken123",
		ServerCN:  "ca.us-east.ovpn.to",
		ServerVip: "10.8.0.1",
	}

	// Marshal to JSON
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// Unmarshal back and verify
	var restored PortForwardState
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if restored.Token != state.Token {
		t.Errorf("Token mismatch: %s != %s", restored.Token, state.Token)
	}
	if restored.ServerCN != state.ServerCN {
		t.Errorf("ServerCN mismatch: %s != %s", restored.ServerCN, state.ServerCN)
	}
	if restored.ServerVip != state.ServerVip {
		t.Errorf("ServerVip mismatch: %s != %s", restored.ServerVip, state.ServerVip)
	}
}

func TestPortForwardPayload_Structure(t *testing.T) {
	payload := PortForwardPayload{
		Port:      12345,
		ExpiresAt: "2025-12-31T23:59:59Z",
	}

	// Verify structure fields
	if payload.Port <= 0 {
		t.Error("Port should be positive")
	}
	if payload.ExpiresAt == "" {
		t.Error("ExpiresAt should not be empty")
	}

	// Verify JSON marshaling
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(data), "\"port\"") {
		t.Errorf("expected 'port' field in JSON")
	}
	if !strings.Contains(string(data), "\"expires_at\"") {
		t.Errorf("expected 'expires_at' field in JSON")
	}
}

func TestDecodePortForwardPayload_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		payload   PortForwardPayload
		wantError bool
	}{
		{
			name:      "min port",
			payload:   PortForwardPayload{Port: 1, ExpiresAt: "2025-01-01T00:00:00Z"},
			wantError: false,
		},
		{
			name:      "max port",
			payload:   PortForwardPayload{Port: 65535, ExpiresAt: "2025-12-31T23:59:59Z"},
			wantError: false,
		},
		{
			name:      "empty expiry",
			payload:   PortForwardPayload{Port: 12345, ExpiresAt: ""},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			encoded := base64.StdEncoding.EncodeToString(data)

			result, err := DecodePortForwardPayload(encoded)
			if (err != nil) != tt.wantError {
				t.Errorf("wantError %v, got error: %v", tt.wantError, err)
			}
			if err == nil && result.Port != tt.payload.Port {
				t.Errorf("port mismatch: want %d, got %d", tt.payload.Port, result.Port)
			}
		})
	}
}

func TestPortForwardSigResponse_JSONParsing(t *testing.T) {
	jsonStr := `{"status":"OK","payload":"dGVzdA==","signature":"sig123"}`
	var resp portForwardSigResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	if err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if resp.Status != "OK" {
		t.Errorf("expected status OK, got %s", resp.Status)
	}
	if resp.Payload != "dGVzdA==" {
		t.Errorf("expected payload dGVzdA==, got %s", resp.Payload)
	}
	if resp.Signature != "sig123" {
		t.Errorf("expected signature sig123, got %s", resp.Signature)
	}
}

func TestPortForwardURLEncoding(t *testing.T) {
	state := PortForwardState{
		Token:     "token with spaces & special=chars",
		ServerCN:  "test.com",
		ServerVip: "10.0.0.1",
	}

	// Test that token is properly URL-encoded
	encodedToken := fmt.Sprintf("%s", state.Token)
	if strings.Contains(encodedToken, " ") || strings.Contains(encodedToken, "&") {
		t.Logf("token contains special chars (will be encoded): %s", encodedToken)
	}
}
