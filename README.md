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
	"time"

	authpb "github.com/your/module/proto"
	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
)

var (
	// Replace this with actual lookup per user
	knownPublicKeys = map[string]ed25519.PublicKey{}
)

type server struct {
	authpb.UnimplementedAuthServiceServer
	kv nats.KeyValue
}

func (s *server) GetChallenge(ctx context.Context, req *authpb.ChallengeRequest) (*authpb.ChallengeResponse, error) {
	challenge := make([]byte, 32)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	// Store the challenge in NATS KV with a TTL of 120 seconds
	err = s.kv.PutString(req.Username, base64.StdEncoding.EncodeToString(challenge))
	if err != nil {
		return nil, err
	}
	s.kv.Watch(req.Username)
	s.kv.Update(req.Username, []byte(base64.StdEncoding.EncodeToString(challenge)))
	s.kv.Create(req.Username, []byte(base64.StdEncoding.EncodeToString(challenge)))

	return &authpb.ChallengeResponse{Challenge: challenge}, nil
}

func (s *server) Authenticate(ctx context.Context, req *authpb.AuthRequest) (*authpb.AuthResponse, error) {
	entry, err := s.kv.Get(req.Username)
	if err != nil {
		return &authpb.AuthResponse{Success: false, Message: "no challenge issued"}, nil
	}
	challenge, err := base64.StdEncoding.DecodeString(string(entry.Value()))
	if err != nil {
		return &authpb.AuthResponse{Success: false, Message: "invalid challenge encoding"}, nil
	}

	pubKey, ok := knownPublicKeys[req.Username]
	if !ok {
		return &authpb.AuthResponse{Success: false, Message: "unknown user"}, nil
	}

	if !ed25519.Verify(pubKey, challenge, req.Signature) {
		return &authpb.AuthResponse{Success: false, Message: "invalid signature"}, nil
	}

	s.kv.Delete(req.Username)

	return &authpb.AuthResponse{Success: true, Message: "authenticated"}, nil
}

func main() {
	// Connect to NATS
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("failed to connect to NATS: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("failed to get JetStream context: %v", err)
	}
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      "xtcp_auth_challenges",
		TTL:         120 * time.Second,
		MaxValueSize: 512,
	})
	if err != nil {
		log.Fatalf("failed to create KV bucket: %v", err)
	}

	// Generate dummy keypair for demo
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	knownPublicKeys["alice"] = pub

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	authpb.RegisterAuthServiceServer(grpcServer, &server{kv: kv})
	fmt.Println("gRPC auth server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
```
