# go_auth_example
go_auth_example

ed25519 based auth example

```
syntax = "proto3";

service AuthService {
  rpc Authenticate(AuthRequest) returns (AuthResponse);
}

message AuthRequest {
  string username = 1;
  string timestamp = 2; // Optional, for replay protection
  bytes signature = 3;
}

message AuthResponse {
  bool success = 1;
  string message = 2;
}
```

```
import (
    "crypto/ed25519"
    "crypto/rand"
    "time"
)

func createAuthRequest(username string, privKey ed25519.PrivateKey) (*AuthRequest, error) {
    ts := time.Now().UTC().Format(time.RFC3339)
    message := []byte(username + ts)
    signature := ed25519.Sign(privKey, message)

    return &AuthRequest{
        Username:  username,
        Timestamp: ts,
        Signature: signature,
    }, nil
}
```

```
import (
    "crypto/ed25519"
    "errors"
)

func verifyAuthRequest(req *AuthRequest, pubKey ed25519.PublicKey) error {
    message := []byte(req.Username + req.Timestamp)
    if !ed25519.Verify(pubKey, message, req.Signature) {
        return errors.New("invalid signature")
    }

    return nil
}
```
