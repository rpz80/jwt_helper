package jwt_helper

import (
	"bytes"
	"encoding/json"
	"testing"
)

type Payload struct {
	Sub  string
	Name string
	Iat  int64
}

const (
	secret = "Top secret"
)

var (
	payload = Payload{
		Sub:  "1234567890",
		Name: "John Doe",
		Iat:  1516239022,
	}
)

func doTest(t *testing.T, createTokenFunc func(t *testing.T) (string, error)) {
	token, err := createTokenFunc(t)
	if err != nil {
		t.Errorf("unexpected token creation failure: %v", err)
	}
	p := Payload{}
	err = Parse(token, secret, &p)
	if err != nil {
		t.Error(err)
	}
	if p != payload {
		t.Errorf("%v != %v", payload, p)
	}
}

func marshalPayload(t *testing.T) []byte {
	serializedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Error(err)
	}
	return serializedPayload
}

func createTokenFromString(t *testing.T) (string, error) {
	return CreateToken(string(marshalPayload(t)), secret)
}

func createTokenFromBytes(t *testing.T) (string, error) {
	return CreateToken(marshalPayload(t), secret)
}

func createTokenFromStruct(t *testing.T) (string, error) {
	return CreateToken(payload, secret)
}

func createTokenFromPointerToStruct(t *testing.T) (string, error) {
	return CreateToken(&payload, secret)
}

func TestCreateTokenString(t *testing.T) {
	doTest(t, createTokenFromString)
}

func TestCreateTokenBytes(t *testing.T) {
	doTest(t, createTokenFromBytes)
}

func TestCreateTokenStruct(t *testing.T) {
	doTest(t, createTokenFromStruct)
}

func TestCreateTokenPointerToStruct(t *testing.T) {
	doTest(t, createTokenFromPointerToStruct)
}

func TestParseInvalidHeader(t *testing.T) {
	token, _ := CreateToken(&payload, secret)
	tokenBytes := []byte(token)
	tokenBytes[0] = 'n'
	p := Payload{}
	err := Parse(string(tokenBytes), secret, &p)
	if err == nil {
		t.Errorf("parsing token with invalid header succeeded")
	}
}

func TestParseInvalidPayload(t *testing.T) {
	token, _ := CreateToken(&payload, secret)
	tokenBytes := []byte(token)
	payloadStartPos := bytes.Index(tokenBytes, []byte("."))
	if payloadStartPos == -1 {
		t.Errorf("invalid payload pos")
	}
	tokenBytes[payloadStartPos+1] = 'n'
	p := Payload{}
	err := Parse(string(tokenBytes), secret, &p)
	if err == nil {
		t.Errorf("parsing token with invalid payload succeeded")
	}
}

func TestParseInvalidSignature(t *testing.T) {
	token, _ := CreateToken(&payload, secret)
	tokenBytes := []byte(token)
	signatureStartPos := bytes.LastIndexAny(tokenBytes, ".")
	if signatureStartPos == -1 {
		t.Errorf("invalid signature pos")
	}
	tokenBytes[signatureStartPos+1] = 'n'
	p := Payload{}
	err := Parse(string(tokenBytes), secret, &p)
	if err == nil {
		t.Errorf("parsing token with invalid signature succeeded")
	}
}
