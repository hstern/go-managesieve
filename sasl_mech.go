// Copyright 2026 The go-managesieve Authors
// SPDX-License-Identifier: Apache-2.0

package managesieve

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// External returns a SASLClient implementing the SASL EXTERNAL mechanism
// (RFC 4422 Appendix A), where the credentials are established by the
// outer layer — typically a TLS client certificate. identity is the
// optional authorization identity to act as ("" to use the one the
// certificate maps to).
func External(identity string) SASLClient { return &externalClient{identity: identity} }

type externalClient struct{ identity string }

func (e *externalClient) Start() (string, []byte, error) {
	return "EXTERNAL", []byte(e.identity), nil
}

func (e *externalClient) Next([]byte) ([]byte, error) {
	return nil, errors.New("managesieve: EXTERNAL expects no server challenge")
}

// OAuthBearer returns a SASLClient implementing the OAUTHBEARER mechanism
// (RFC 7628). username is the authorization identity (may be ""); token
// is the OAuth 2.0 bearer token (without the "Bearer " prefix). Use only
// over a confidential (TLS) channel.
func OAuthBearer(username, token string) SASLClient {
	return &oauthBearerClient{username: username, token: token}
}

type oauthBearerClient struct{ username, token string }

func (o *oauthBearerClient) Start() (string, []byte, error) {
	gs2 := "n,,"
	if o.username != "" {
		gs2 = "n,a=" + o.username + ","
	}
	ir := gs2 + "\x01auth=Bearer " + o.token + "\x01\x01"
	return "OAUTHBEARER", []byte(ir), nil
}

func (o *oauthBearerClient) Next([]byte) ([]byte, error) {
	// On failure the server sends a JSON error as a challenge; per RFC 7628
	// the client acknowledges with a single %x01 and the server then fails
	// the exchange.
	return []byte{0x01}, nil
}

// ScramSHA256 returns a SASLClient implementing SCRAM-SHA-256 (RFC 7677,
// RFC 5802) without channel binding. It performs mutual authentication:
// the server's signature is verified via the SASLFinalReceiver path.
func ScramSHA256(username, password string) SASLClient {
	return &scramClient{username: username, password: password}
}

type scramClient struct {
	username, password string
	nonce              string // client nonce; generated in Start when empty
	clientFirstBare    string
	serverSignature    []byte
	step               int
}

func (s *scramClient) Start() (string, []byte, error) {
	if s.nonce == "" {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return "", nil, err
		}
		s.nonce = base64.StdEncoding.EncodeToString(b)
	}
	s.clientFirstBare = "n=" + scramEscape(s.username) + ",r=" + s.nonce
	return "SCRAM-SHA-256", []byte("n,," + s.clientFirstBare), nil
}

func (s *scramClient) Next(challenge []byte) ([]byte, error) {
	s.step++
	switch s.step {
	case 1:
		return s.serverFirst(string(challenge))
	case 2:
		// Some servers send the server-final ("v=...") as a challenge
		// rather than on the success line; verify and answer empty.
		if err := s.verify(string(challenge)); err != nil {
			return nil, err
		}
		return []byte{}, nil
	default:
		return nil, errors.New("managesieve: unexpected SCRAM challenge")
	}
}

// SASLFinal verifies the server signature carried on the success line.
func (s *scramClient) SASLFinal(data []byte) error { return s.verify(string(data)) }

func (s *scramClient) serverFirst(msg string) ([]byte, error) {
	attrs := scramParse(msg)
	rnonce := attrs["r"]
	if rnonce == "" || !strings.HasPrefix(rnonce, s.nonce) {
		return nil, errors.New("managesieve: SCRAM server nonce does not extend the client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return nil, errors.New("managesieve: SCRAM: bad salt")
	}
	iter, err := strconv.Atoi(attrs["i"])
	if err != nil || iter <= 0 {
		return nil, errors.New("managesieve: SCRAM: bad iteration count")
	}
	saltedPassword, err := pbkdf2.Key(sha256.New, s.password, salt, iter, sha256.Size)
	if err != nil {
		return nil, err
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	// "biws" is base64("n,,") — the GS2 header without channel binding.
	clientFinalBare := "c=biws,r=" + rnonce
	authMessage := s.clientFirstBare + "," + msg + "," + clientFinalBare

	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	s.serverSignature = hmacSHA256(serverKey, []byte(authMessage))

	return []byte(clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(clientProof)), nil
}

func (s *scramClient) verify(serverFinal string) error {
	attrs := scramParse(serverFinal)
	if e := attrs["e"]; e != "" {
		return errors.New("managesieve: SCRAM authentication failed: " + e)
	}
	got, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil {
		return errors.New("managesieve: SCRAM: bad server signature encoding")
	}
	if s.serverSignature == nil || !hmac.Equal(got, s.serverSignature) {
		return errors.New("managesieve: SCRAM server signature mismatch")
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// scramParse splits a SCRAM message ("k=v,k=v,...") into attributes,
// taking everything after the first '=' as the value (base64 values may
// contain '=').
func scramParse(msg string) map[string]string {
	out := map[string]string{}
	for part := range strings.SplitSeq(msg, ",") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

// scramEscape applies SCRAM username escaping: ',' -> "=2C", '=' -> "=3D".
func scramEscape(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}
