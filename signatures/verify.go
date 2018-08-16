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
	"crypto/x509"

	"github.com/pkg/errors"

	"github.com/stratumn/go-crypto/encoding"
	"github.com/stratumn/go-crypto/keys"
	"golang.org/x/crypto/ed25519"
)

// ErrInvalidSignature is the error returned when the signature verification failed
var ErrInvalidSignature = errors.New("signature verification failed")

// Verify checks the signature of a message for a given public key,
// it returns nil if the signature is correct. Except for ED25519 signatures
// it relies on x509 signature check for certificates.
func Verify(signature *Signature) error {
	pk, ai, err := keys.ParsePublicKey(signature.PublicKey)
	if err != nil {
		return err
	}

	sigBytes, err := encoding.DecodePEM(signature.Signature, SignaturePEMLabel)
	if err != nil {
		return err
	}

	algo, err := getSignatureAlgorithmFromIdentifier(ai.Algorithm)
	if err != nil {
		return err
	}

	if algo == x509.UnknownSignatureAlgorithm {
		return errors.New("unknown public key algorithm")
	}

	if algo == PureED25519 {
		if pub, ok := pk.(*ed25519.PublicKey); ok {
			if ed25519.Verify(*pub, signature.Message, sigBytes) {
				return nil
			}
			return errors.Wrap(ErrInvalidSignature, "invalid ed25519 signature")
		}
		return errors.Wrap(ErrInvalidSignature, "incorrect ed25519 public key")
	}

	crt := x509.Certificate{PublicKey: pk}
	if err := crt.CheckSignature(algo, signature.Message, sigBytes); err != nil {
		return errors.Wrap(ErrInvalidSignature, err.Error())
	}
	return nil
}
