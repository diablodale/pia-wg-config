package pia

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/pkg/errors"
)

// PortForwardState holds everything needed to obtain and refresh a PIA port-forward
// after the WireGuard tunnel is up.  Write this to a JSON file alongside the WG config
// and pass it to the 'port-forward' command once the tunnel is active.
type PortForwardState struct {
	Token     string `json:"token"`
	ServerCN  string `json:"server_cn"`
	ServerVip string `json:"server_vip"` // VPN gateway IP, reachable inside the tunnel
}

// PortForwardPayload is the decoded content of the base64 payload returned by /getSignature.
type PortForwardPayload struct {
	Port      int    `json:"port"`
	ExpiresAt string `json:"expires_at"`
}

type portForwardSigResponse struct {
	Status    string `json:"status"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// NewPIAClientForPortForward creates a minimal PIAClient for use with the port-forward
// workflow.  No credentials or region selection are needed; only the CA cert for TLS.
func NewPIAClientForPortForward(caCertPath string, verbose bool) (*PIAClient, error) {
	p := &PIAClient{
		caCertPath: caCertPath,
		verbose:    verbose,
	}
	if err := p.downloadPIACertificate(); err != nil {
		return nil, errors.Wrap(err, "loading PIA CA certificate")
	}
	return p, nil
}

// GetPortForwardSignature calls /getSignature on the PIA port-forward API.
//
// The TCP connection is made to state.ServerVip:19999, but TLS is verified against
// state.ServerCN — the same connect-to trick used by PIA's bash scripts.
// This MUST be called after the WireGuard tunnel is active; ServerVip is only
// reachable from inside the tunnel.
func (p *PIAClient) GetPortForwardSignature(state PortForwardState) (payload, signature string, err error) {
	server := Server{Cn: state.ServerCN, IP: state.ServerVip}
	reqURL := fmt.Sprintf("https://%s:19999/getSignature?token=%s",
		state.ServerCN, url.QueryEscape(state.Token))

	resp, err := p.executePIARequest(server, reqURL)
	if err != nil {
		return "", "", errors.Wrap(err, "getSignature request failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", "", errors.Wrap(err, "reading getSignature response")
	}

	var sig portForwardSigResponse
	if err := json.Unmarshal(body, &sig); err != nil {
		return "", "", errors.Wrap(err, "decoding getSignature response")
	}
	if sig.Status != "OK" {
		return "", "", fmt.Errorf("getSignature returned non-OK status: %s", sig.Status)
	}

	return sig.Payload, sig.Signature, nil
}

// DecodePortForwardPayload base64-decodes and JSON-parses the payload from /getSignature.
func DecodePortForwardPayload(payload string) (PortForwardPayload, error) {
	// PIA uses standard base64 with padding; fall back to raw (no-padding) if that fails.
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(payload)
		if err != nil {
			return PortForwardPayload{}, errors.Wrap(err, "base64-decoding PF payload")
		}
	}

	var pf PortForwardPayload
	if err := json.Unmarshal(data, &pf); err != nil {
		return PortForwardPayload{}, errors.Wrap(err, "JSON-decoding PF payload")
	}
	return pf, nil
}

// BindPort calls /bindPort on the PIA port-forward API to activate or refresh the port.
// Call this immediately after GetPortForwardSignature and then every ~15 minutes to
// keep the forwarded port alive.
func (p *PIAClient) BindPort(state PortForwardState, payload, signature string) error {
	server := Server{Cn: state.ServerCN, IP: state.ServerVip}
	reqURL := fmt.Sprintf("https://%s:19999/bindPort?payload=%s&signature=%s",
		state.ServerCN, url.QueryEscape(payload), url.QueryEscape(signature))

	resp, err := p.executePIARequest(server, reqURL)
	if err != nil {
		return errors.Wrap(err, "bindPort request failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return errors.Wrap(err, "reading bindPort response")
	}

	var result struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return errors.Wrap(err, "decoding bindPort response")
	}
	if result.Status != "OK" {
		return fmt.Errorf("bindPort returned non-OK status %q: %s", result.Status, result.Message)
	}
	return nil
}
