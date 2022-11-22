package jwt_helper

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	header string = `{"alg": "HS256", "typ": "JWT"}`
)

// Payload might be a serialized to JSON struct (string or []byte) or an object
// which can be serialized to JSON.
func CreateToken(payload any, secret string) (string, error) {
	var payloadB64 []byte
	if s, ok := payload.(string); ok {
		payloadB64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(s)))
		base64.RawURLEncoding.Encode(payloadB64, []byte(s))
	} else if b, ok := payload.([]byte); ok {
		payloadB64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(b)))
		base64.RawURLEncoding.Encode(payloadB64, b)
	} else {
		payloadJson, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}

		payloadB64 = make([]byte, base64.RawURLEncoding.EncodedLen(len(payloadJson)))
		base64.RawURLEncoding.Encode(payloadB64, payloadJson)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(header))
	signatureB64 := createSignature(headerB64, string(payloadB64), secret)
	return headerB64 + "." + string(payloadB64) + "." + signatureB64, nil
}

func createSignature(headerB64 string, payloadB64 string, secret string) string {
	hasher := hmac.New(sha256.New, []byte(secret))
	hasher.Write([]byte(headerB64))
	hasher.Write([]byte("."))
	hasher.Write([]byte(payloadB64))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

// Payload should be a pointer to a struct which is supposed to be deserialized
// to from the token JSON payload.
func Parse(token string, secret string, payload any) error {
	splits := strings.Split(token, ".")
	if len(splits) != 3 {
		return errors.New("invalid token")
	}

	// Header
	buffer := make([]byte, base64.RawURLEncoding.DecodedLen(len(splits[0])))
	_, err := base64.RawURLEncoding.Decode(buffer, []byte(splits[0]))
	if err != nil {
		return errors.New("failed to decode header")
	}

	if string(buffer) != header {
		return fmt.Errorf("invalid header: %v", buffer)
	}

	// Payload
	buffer = make([]byte, base64.RawURLEncoding.DecodedLen(len(splits[1])))
	_, err = base64.RawURLEncoding.Decode(buffer, []byte(splits[1]))
	if err != nil {
		return fmt.Errorf("failed to decode payload from Base64:  %v", err)
	}

	err = json.Unmarshal([]byte(buffer), payload)
	if err != nil {
		return fmt.Errorf("failed to deserialize JSON payload: %v", err)
	}

	// Signature
	signature := createSignature(splits[0], splits[1], secret)
	if signature != splits[2] {
		return errors.New("invalid signature")
	}

	return nil
}
