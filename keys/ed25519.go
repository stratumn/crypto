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
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/stratumn/go-crypto/encoding"
	"golang.org/x/crypto/ed25519"
)

const (
	// ED25519SecretPEMLabel is the label of a PEM-encoded ED25519 secret key.
	ED25519SecretPEMLabel = "ED25519 PRIVATE KEY"

	// ED25519PublicPEMLabel is the label of a PEM-encoded ED25519 public key.
	ED25519PublicPEMLabel = "ED25519 PUBLIC KEY"
)

// NewEd25519KeyPair generates a new ed25519 key pair.
func NewEd25519KeyPair() (crypto.PublicKey, *ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &pub, &priv, nil
}

// EncodeED25519SecretKey encodes an ed25519 secret key using ASN.1
func EncodeED25519SecretKey(sk *ed25519.PrivateKey) ([]byte, error) {
	skBytes, err := asn1.Marshal(*sk)
	if err != nil {
		return nil, err
	}

	privKeyInfo := pkcs8PrivateKey{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: OIDPublicKeyED25519},
		PrivateKey: skBytes,
	}
	privKey, err := asn1.Marshal(privKeyInfo)
	if err != nil {
		return nil, err
	}

	return encoding.EncodePEM(privKey, ED25519SecretPEMLabel)
}

// UnmarshalED25519Key unmarshals an ASN1. DER encoded private key of type ED25519.
func UnmarshalED25519Key(sk []byte) (*ed25519.PrivateKey, *ed25519.PublicKey, error) {
	var data ed25519.PrivateKey
	_, err := asn1.Unmarshal(sk, &data)
	if err != nil {
		return nil, nil, err
	}

	pub := data.Public().(ed25519.PublicKey)
	return &data, &pub, nil
}
