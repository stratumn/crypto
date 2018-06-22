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
func EncodeED25519SecretKey(sk *ed25519.PrivateKey) (string, error) {
	skBytes, err := asn1.Marshal(*sk)
	if err != nil {
		return "", err
	}
	return encoding.EncodePEM(skBytes, ED25519SecretPEMLabel)
}

// ParseED25519Key decodes a PEM block containing an ASN1. DER encoded private key of type ED25519.
func ParseED25519Key(sk string) (*ed25519.PrivateKey, *ed25519.PublicKey, error) {
	DERBytes, err := encoding.DecodePEM(sk, ED25519SecretPEMLabel)
	if err != nil {
		return nil, nil, err
	}

	var data ed25519.PrivateKey
	_, err = asn1.Unmarshal(DERBytes, &data)
	if err != nil {
		return nil, nil, err
	}

	pub := data.Public().(ed25519.PublicKey)
	return &data, &pub, nil
}
