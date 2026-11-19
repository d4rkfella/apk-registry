package registry

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type signingKeyInfo struct {
	id           string
	publicName   string
	publicKey    *rsa.PublicKey
	publicKeyPEM []byte
}

func loadSigningKey(privateKeyPath string) (*signingKeyInfo, error) {
	base := filepath.Base(privateKeyPath)
	if !strings.HasSuffix(base, ".rsa") || len(base) == len(".rsa") {
		return nil, errors.New("signing key filename must end in .rsa")
	}
	privatePEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("signing key does not contain a PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA signing key: %w", err)
	}
	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("validate RSA signing key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal RSA public key: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if len(publicPEM) == 0 {
		return nil, errors.New("encode RSA public key")
	}

	return &signingKeyInfo{
		id:           strings.TrimSuffix(base, ".rsa"),
		publicName:   base + ".pub",
		publicKey:    &privateKey.PublicKey,
		publicKeyPEM: publicPEM,
	}, nil
}
