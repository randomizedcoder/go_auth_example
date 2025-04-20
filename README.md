# go_auth_example
go_auth_example

ed25519 based auth example

```
syntax = "proto3";

package auth;

service AuthService {
  // Step 1: client requests challenge
  rpc GetChallenge(ChallengeRequest) returns (ChallengeResponse);

  // Step 2: client responds with signed challenge
  rpc Authenticate(AuthRequest) returns (AuthResponse);
}

message ChallengeRequest {
  string username = 1;
}

message ChallengeResponse {
  bytes challenge = 1;
}

message AuthRequest {
  string username = 1;
  bytes challenge = 2;
  bytes signature = 3;
}

message AuthResponse {
  bool success = 1;
  string message = 2;
} 

```

```
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	authpb "github.com/your/module/proto"
	"google.golang.org/grpc"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("could not connect: %v", err)
	}
	defer conn.Close()

	client := authpb.NewAuthServiceClient(conn)
	username := "alice"

	// Generate keypair (in real use: load from disk)
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen failed: %v", err)
	}

	// Step 1: Request challenge
	res1, err := client.GetChallenge(context.Background(), &authpb.ChallengeRequest{
		Username: username,
	})
	if err != nil {
		log.Fatalf("GetChallenge failed: %v", err)
	}
	fmt.Printf("Received challenge: %x\n", res1.Challenge)

	// Step 2: Sign challenge
	sig := ed25519.Sign(privKey, res1.Challenge)
	res2, err := client.Authenticate(context.Background(), &authpb.AuthRequest{
		Username:  username,
		Challenge: res1.Challenge,
		Signature: sig,
	})
	if err != nil {
		log.Fatalf("Authenticate failed: %v", err)
	}

	fmt.Printf("Authenticated: %v (%s)\n", res2.Success, res2.Message)
}

```

```
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	authpb "github.com/your/module/proto"
	"google.golang.org/grpc"
)

// In-memory challenge store (in production use a DB or cache)
var (
	challenges   = make(map[string][]byte)
	challengesMu sync.Mutex

	// Replace this with actual lookup per user
	knownPublicKeys = map[string]ed25519.PublicKey{}
)

type server struct {
	authpb.UnimplementedAuthServiceServer
}

func (s *server) GetChallenge(ctx context.Context, req *authpb.ChallengeRequest) (*authpb.ChallengeResponse, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	challengesMu.Lock()
	challenges[req.Username] = challenge
	challengesMu.Unlock()
	return &authpb.ChallengeResponse{Challenge: challenge}, nil
}

func (s *server) Authenticate(ctx context.Context, req *authpb.AuthRequest) (*authpb.AuthResponse, error) {
	challengesMu.Lock()
	challenge, ok := challenges[req.Username]
	challengesMu.Unlock()
	if !ok {
		return &authpb.AuthResponse{Success: false, Message: "no challenge issued"}, nil
	}

	pubKey, ok := knownPublicKeys[req.Username]
	if !ok {
		return &authpb.AuthResponse{Success: false, Message: "unknown user"}, nil
	}

	if !ed25519.Verify(pubKey, challenge, req.Signature) {
		return &authpb.AuthResponse{Success: false, Message: "invalid signature"}, nil
	}

	// Optional: delete challenge after use
	challengesMu.Lock()
	delete(challenges, req.Username)
	challengesMu.Unlock()

	return &authpb.AuthResponse{Success: true, Message: "authenticated"}, nil
}

func main() {
	// Generate dummy keypair for demo
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	knownPublicKeys["alice"] = pub

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	authpb.RegisterAuthServiceServer(grpcServer, &server{})
	fmt.Println("gRPC auth server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
```
