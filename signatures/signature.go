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
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

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

// ErrNotImplemented is the error returned when trying to sign a message wit an uninmplemented algorithm.
var ErrNotImplemented = errors.New("Unhandled signature algorithm")

// Signature describes a signed message. It contains:
// - the digital signature algorithm used to sign the message
// - the publicKey of the signer
// - the original message
// - the signature. Depending on the algorithm, either the whole message or just a hash of it is signed.
type Signature struct {
	AI        string `json:"algorithm"`
	PublicKey []byte `json:"public_key"`
	Message   []byte `json:"messsage"`
	Signature []byte `json:"signature"`
}

// ParseSignature deserializes a signature from a PEM format.
func ParseSignature(sigBytes []byte) (*Signature, error) {
	DERBytes, err := encoding.DecodePEM(sigBytes, SignaturePEMLabel)
	if err != nil {
		return nil, err
	}

	var sig Signature
	if _, err := asn1.Unmarshal(DERBytes, &sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// Encode serializes a signature to the PEM format.
func (s *Signature) Encode() ([]byte, error) {
	sigBytes, err := asn1.Marshal(s)
	if err != nil {
		return nil, err
	}
	return encoding.EncodePEM(sigBytes, SignaturePEMLabel)
}

var algoName = [...]string{
	x509.MD2WithRSA:       "MD2-RSA",
	x509.MD5WithRSA:       "MD5-RSA",
	x509.SHA1WithRSA:      "SHA1-RSA",
	x509.SHA256WithRSA:    "SHA256-RSA",
	x509.SHA384WithRSA:    "SHA384-RSA",
	x509.SHA512WithRSA:    "SHA512-RSA",
	x509.SHA256WithRSAPSS: "SHA256-RSAPSS",
	x509.SHA384WithRSAPSS: "SHA384-RSAPSS",
	x509.SHA512WithRSAPSS: "SHA512-RSAPSS",
	x509.DSAWithSHA1:      "DSA-SHA1",
	x509.DSAWithSHA256:    "DSA-SHA256",
	x509.ECDSAWithSHA1:    "ECDSA-SHA1",
	x509.ECDSAWithSHA256:  "ECDSA-SHA256",
	x509.ECDSAWithSHA384:  "ECDSA-SHA384",
	x509.ECDSAWithSHA512:  "ECDSA-SHA512",
	PureED25519:           "ED25519",
}

func getSignatureAlgorithmFromIdentifier(algo string) (x509.SignatureAlgorithm, error) {
	for id, supportedAlgo := range algoName {
		if algo == supportedAlgo {
			return x509.SignatureAlgorithm(id), nil
		}
	}
	return x509.UnknownSignatureAlgorithm, x509.ErrUnsupportedAlgorithm
}

// List of object identifiers for signature algorithms and hash functions.
var (
	OIDSignatureMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	OIDSignatureMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	OIDSignatureSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	OIDSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSignatureDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	OIDSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	OIDSignatureECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	OIDSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSignaturePureED25519     = asn1.ObjectIdentifier{1, 3, 101, 112}

	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	OIDMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

	OIDISOSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}
)

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, OIDSignatureMD2WithRSA, x509.RSA, crypto.Hash(0)},
	{x509.MD5WithRSA, OIDSignatureMD5WithRSA, x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, OIDSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, OIDISOSignatureSHA1WithRSA, x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, OIDSignatureSHA256WithRSA, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, OIDSignatureSHA384WithRSA, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, OIDSignatureSHA512WithRSA, x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, OIDSignatureRSAPSS, x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, OIDSignatureRSAPSS, x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, OIDSignatureRSAPSS, x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, OIDSignatureDSAWithSHA1, x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, OIDSignatureDSAWithSHA256, x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, OIDSignatureECDSAWithSHA1, x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, OIDSignatureECDSAWithSHA256, x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, OIDSignatureECDSAWithSHA384, x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, OIDSignatureECDSAWithSHA512, x509.ECDSA, crypto.SHA512},
	{PureED25519, OIDSignaturePureED25519, keys.ED25519, crypto.Hash(0)},
}

func getSignatureAlgorithmFromAI(ai pkix.AlgorithmIdentifier) x509.SignatureAlgorithm {
	if !ai.Algorithm.Equal(OIDSignatureRSAPSS) {
		for _, details := range signatureAlgorithmDetails {
			if ai.Algorithm.Equal(details.oid) {
				return details.algo
			}
		}
		return x509.UnknownSignatureAlgorithm
	}

	// RSA PSS is special because it encodes important parameters
	// in the Parameters.

	var params pssParameters
	if _, err := asn1.Unmarshal(ai.Parameters.FullBytes, &params); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	var mgf1HashFunc pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(params.MGF.Parameters.FullBytes, &mgf1HashFunc); err != nil {
		return x509.UnknownSignatureAlgorithm
	}

	// PSS is greatly overburdened with options. This code forces
	// them into three buckets by requiring that the MGF1 hash
	// function always match the message hash function (as
	// recommended in
	// https://tools.ietf.org/html/rfc3447#section-8.1), that the
	// salt length matches the hash length, and that the trailer
	// field has the default value.
	if !bytes.Equal(params.Hash.Parameters.FullBytes, asn1.NullBytes) ||
		!params.MGF.Algorithm.Equal(OIDMGF1) ||
		!mgf1HashFunc.Algorithm.Equal(params.Hash.Algorithm) ||
		!bytes.Equal(mgf1HashFunc.Parameters.FullBytes, asn1.NullBytes) ||
		params.TrailerField != 1 {
		return x509.UnknownSignatureAlgorithm
	}

	switch {
	case params.Hash.Algorithm.Equal(OIDSHA256) && params.SaltLength == 32:
		return x509.SHA256WithRSAPSS
	case params.Hash.Algorithm.Equal(OIDSHA384) && params.SaltLength == 48:
		return x509.SHA384WithRSAPSS
	case params.Hash.Algorithm.Equal(OIDSHA512) && params.SaltLength == 64:
		return x509.SHA512WithRSAPSS
	}

	return x509.UnknownSignatureAlgorithm
}

// pssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See https://tools.ietf.org/html/rfc3447#appendix-A.2.3
type pssParameters struct {
	// The following three fields are not marked as
	// optional because the default values specify SHA-1,
	// which is no longer suitable for use in signatures.
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}
