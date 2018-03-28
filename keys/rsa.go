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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/stratumn/crypto/encoding"
)

const (
	// RSAKeySize is the size of the created RSA key. This is not yet configurable but it should be in the future.
	RSAKeySize = 4096

	// RSASecretPEMLabel is the label of a PEM-encoded RSA secret key.
	RSASecretPEMLabel = "RSA PRIVATE KEY"

	// RSAPublicPEMLabel is the label of a PEM-encoded RSA public key.
	RSAPublicPEMLabel = "RSA PUBLIC KEY"
)

// NewRSAKeyPair generates a new RSA key pair.
func NewRSAKeyPair() (crypto.PublicKey, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, nil, err
	}
	return priv.Public(), priv, nil
}

// EncodeRSASecretKey encodes an RSA key in ASN.1 DER format within a PEM block.
func EncodeRSASecretKey(sk *rsa.PrivateKey) ([]byte, error) {
	skBytes := x509.MarshalPKCS1PrivateKey(sk)
	return encoding.EncodePEM(skBytes, RSASecretPEMLabel)
}

// ParseRSAKey decodes a PEM block containing an ASN1. DER encoded private key of type RSA.
func ParseRSAKey(sk []byte) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	DERBytes, err := encoding.DecodePEM(sk, RSASecretPEMLabel)
	if err != nil {
		return nil, nil, err
	}

	data, err := x509.ParsePKCS1PrivateKey(DERBytes)
	if err != nil {
		return nil, nil, err
	}

	return data, data.Public().(*rsa.PublicKey), nil
}
