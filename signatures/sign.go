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

package signatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/pkg/errors"
	"github.com/stratumn/go-crypto/encoding"
	"github.com/stratumn/go-crypto/keys"
	"golang.org/x/crypto/ed25519"
)

// Sign signs a message with the private key.
// It returns a Signature object containing the public key, the identifier for the signature algorithm used,
// the message that was signed and the signature.
// The secretKey argument must be the content of a PEM file containing the secret key.
func Sign(secretKey, msg []byte) (*Signature, error) {
	sk, pk, err := keys.ParseSecretKey(secretKey)
	if err != nil {
		return nil, err
	}

	signer, ok := sk.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key does not implement crypto.Signer")
	}

	var signed []byte
	var opts crypto.SignerOpts
	switch sk.(type) {
	case *ed25519.PrivateKey:
		if len(*sk.(*ed25519.PrivateKey)) != ed25519.PrivateKeySize {
			return nil, errors.Errorf("ED25519 private key length must be %d, got %d", ed25519.PrivateKeySize, len(*sk.(*ed25519.PrivateKey)))
		}
		signed = msg
		opts = crypto.Hash(0)
	case *ecdsa.PrivateKey:
		h := sha256.New()
		h.Write(msg)
		signed = h.Sum(nil)
		opts = crypto.SHA256
	case *rsa.PrivateKey:
		h := sha256.New()
		h.Write(msg)
		signed = h.Sum(nil)
		opts = crypto.SHA256
	default:
		return nil, ErrNotImplemented
	}

	signature, err := signer.Sign(rand.Reader, signed, opts)
	if err != nil {
		return nil, err
	}

	PEMSignature, err := encoding.EncodePEM(signature, SignaturePEMLabel)
	if err != nil {
		return nil, err
	}

	PEMPublicKey, err := keys.EncodePublicKey(pk)
	if err != nil {
		return nil, err
	}

	return &Signature{
		Signature: PEMSignature,
		Message:   msg,
		PublicKey: PEMPublicKey,
	}, nil
}
