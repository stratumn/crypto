// Copyright 2017 Stratumn SAS. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"

	"github.com/pkg/errors"
	"github.com/stratumn/go-crypto/encoding"

	"golang.org/x/crypto/ed25519"
)

const (
	// GenericPublicPEMLabel is the label of the PEM key in case the key algoritm is not identified.
	GenericPublicPEMLabel = "PUBLIC KEY"

	// ED25519 is a public key algorithm currently not supported in x509
	ED25519 x509.PublicKeyAlgorithm = iota + 1000
)

var (
	// ErrNotImplemented is the error returned if the key algorithm is not implemented.
	ErrNotImplemented = errors.New("key algorithm not implemented")

	// HandledPublicKeys are the public keys which we are able to parse
	HandledPublicKeys = []string{ED25519PublicPEMLabel, ECDSAPublicPEMLabel, RSAPublicPEMLabel, GenericPublicPEMLabel}
)

// List of object identifiers for public keys.
var (
	OIDPublicKeyRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDPublicKeyDSA     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	OIDPublicKeyECDSA   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDPublicKeyED25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// GenerateKey generates a key pair given public key algorithm.
// Available algorithms are: RSA, ECDSA256, RSA.
func GenerateKey(algo x509.PublicKeyAlgorithm) (pubBytes []byte, privBytes []byte, err error) {
	var pub crypto.PublicKey

	switch algo {
	case ED25519:
		var priv *ed25519.PrivateKey
		pub, priv, err = NewEd25519KeyPair()
		if err != nil {
			return nil, nil, err
		}
		privBytes, err = EncodeED25519SecretKey(priv)

	case x509.ECDSA:
		var priv *ecdsa.PrivateKey
		pub, priv, err = NewECDSAKeyPair()
		if err != nil {
			return nil, nil, err
		}
		privBytes, err = EncodeECDSASecretKey(priv)

	case x509.RSA:
		var priv *rsa.PrivateKey
		pub, priv, err = NewRSAKeyPair()
		if err != nil {
			return nil, nil, err
		}
		privBytes, err = EncodeRSASecretKey(priv)
	default:
		err = ErrNotImplemented
	}

	if err != nil {
		return nil, nil, err
	}

	pubBytes, err = EncodePublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	return pubBytes, privBytes, nil
}

/*
 PUBLIC KEYS' ENCODING FUNCTIONS
*/

// MarshalPKIXPublicKey wraps x509.MarshalPublicKey and additionaly handles ED25519 public keys.
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if pk, ok := pub.(*ed25519.PublicKey); ok {
		pkInfo := publicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: OIDPublicKeyED25519,
			},
			PublicKey: asn1.BitString{
				Bytes:     *pk,
				BitLength: ed25519.PrivateKeySize * 8,
			},
		}

		return asn1.Marshal(pkInfo)
	}

	return x509.MarshalPKIXPublicKey(pub)
}

// EncodePublicKey serializes a public key to the PEM format.
func EncodePublicKey(pub crypto.PublicKey) ([]byte, error) {
	DERBytes, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var pemLabel string
	switch pub.(type) {
	case *ed25519.PublicKey:
		pemLabel = ED25519PublicPEMLabel
	case *ecdsa.PublicKey:
		pemLabel = ECDSAPublicPEMLabel
	case *rsa.PublicKey:
		pemLabel = RSAPublicPEMLabel
	default:
		pemLabel = GenericPublicPEMLabel
	}
	return encoding.EncodePEM(DERBytes, pemLabel)
}

// ParsePKIXPublicKey parses a DER encoded public key.
// If of type ED25519 it parses the public key directly,
// if not it relies on x509 public key parser.
func ParsePKIXPublicKey(pk []byte) (crypto.PublicKey, error) {
	var pkInfo publicKeyInfo
	if rest, err := asn1.Unmarshal(pk, &pkInfo); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("trailing data after ASN.1 of public-key")
	}

	if pkInfo.Algorithm.Algorithm.Equal(OIDPublicKeyED25519) {
		if len(pkInfo.PublicKey.Bytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key")
		}
		pub := ed25519.PublicKey(pkInfo.PublicKey.Bytes)
		return &pub, nil
	}

	return x509.ParsePKIXPublicKey(pk)
}

// ParsePublicKey parses a PEM encoded public Key
// If of type ED25519 it parses the public key directly,
// if not it relies on x509 public key parser.
func ParsePublicKey(pk []byte) (crypto.PublicKey, error) {
	for _, keyType := range HandledPublicKeys {
		DERBytes, err := encoding.DecodePEM(pk, keyType)
		if err == encoding.ErrBadPEMFormat {
			return nil, err
		} else if err == nil {
			return ParsePKIXPublicKey(DERBytes)
		}
	}
	return nil, errors.Errorf("Could not parse public key, handled types are: %v", strings.Join(HandledPublicKeys, ", "))
}

/*
 SECRET KEYS' ENCODING FUNCTIONS.
*/

// The following is just a copy of https://golang.org/src/crypto/x509/pkcs8.go
// We need to do this to add the ED25519 key type.
type pkcs8PrivateKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// EncodeSecretkey serializes a secret key to the PEM format.
func EncodeSecretkey(priv crypto.PrivateKey) ([]byte, error) {
	switch priv.(type) {
	case *ed25519.PrivateKey:
		return EncodeED25519SecretKey(priv.(*ed25519.PrivateKey))
	case *ecdsa.PrivateKey:
		return EncodeECDSASecretKey(priv.(*ecdsa.PrivateKey))
	case *rsa.PrivateKey:
		return EncodeRSASecretKey(priv.(*rsa.PrivateKey))
	default:
		return nil, ErrNotImplemented
	}
}

// ParseSecretKey deserializes a secret key from a PEM format.
func ParseSecretKey(sk []byte) (priv crypto.PrivateKey, pub crypto.PublicKey, err error) {
	block, _ := pem.Decode(sk)
	if block == nil {
		return nil, nil, encoding.ErrBadPEMFormat
	}

	var privKeyInfo pkcs8PrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &privKeyInfo); err != nil {
		return nil, nil, err
	}

	algo := privKeyInfo.Algo.Algorithm
	switch {
	case algo.Equal(OIDPublicKeyED25519):
		priv, pub, err = UnmarshalED25519Key(privKeyInfo.PrivateKey)

	case algo.Equal(OIDPublicKeyECDSA):
		priv, pub, err = ParseECDSAPKCS8Key(sk)

	case algo.Equal(OIDPublicKeyRSA):
		priv, pub, err = ParseRSAPKCS8Key(sk)
	}

	if err != nil {
		return nil, nil, err
	}

	return priv, pub, nil
}
