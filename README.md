# jwt_helper
JWT token creation and validation/parsing helpers. Consists of two functions:
1. `func CreateToken(payload any, secret string) (string, error)`. Payload might be a serialized to
JSON struct (string or []byte) or an object which can be serialized to JSON.
2. `func Parse(token string, secret string, payload any) error`. Payload should be a pointer to a
struct which is supposed to be deserialized to from the token JSON payload.
