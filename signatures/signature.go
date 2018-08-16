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

// Package signatures is used to check signatures. Only ED25519 which is not
// yet supported by crypto/x509 is implemented directly, other signatures
// are verified using x509 package.
package signatures

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/stratumn/go-crypto/encoding"
	"github.com/stratumn/go-crypto/keys"
)

// List of signature algorithms supported in addition to x509.
const (
	PureED25519 x509.SignatureAlgorithm = iota + 1000

	// SignaturePEMLabel is the label of a PEM-encoded signed message
	SignaturePEMLabel = "MESSAGE"
)

// ErrNotImplemented is the error returned when trying to sign a message with an unimplemented algorithm.
var ErrNotImplemented = errors.New("Unhandled signature algorithm")

// ParseSignature deserializes a signature from a PEM format.
func ParseSignature(sigBytes []byte) (*Signature, error) {
	jsonSig, err := encoding.DecodePEM(sigBytes, SignaturePEMLabel)
	if err != nil {
		return nil, err
	}

	var sig Signature
	if err := json.Unmarshal(jsonSig, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// Encode serializes a signature to the PEM format.
func (s *Signature) Encode() ([]byte, error) {
	sigBytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return encoding.EncodePEM(sigBytes, SignaturePEMLabel)
}

var signatureAlgorithms = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.SHA256WithRSA:   keys.OIDPublicKeyRSA,
	x509.DSAWithSHA256:   keys.OIDPublicKeyDSA,
	x509.ECDSAWithSHA256: keys.OIDPublicKeyECDSA,
	PureED25519:          keys.OIDPublicKeyED25519,
}

func getSignatureAlgorithmFromIdentifier(algo asn1.ObjectIdentifier) (x509.SignatureAlgorithm, error) {
	for sigAlgo, pkAlgo := range signatureAlgorithms {
		if algo.Equal(pkAlgo) {
			return sigAlgo, nil
		}
	}
	return x509.UnknownSignatureAlgorithm, x509.ErrUnsupportedAlgorithm
}
