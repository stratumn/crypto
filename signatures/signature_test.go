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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stratumn/crypto/encoding"
	"github.com/stratumn/crypto/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var (
	msg      = []byte("message")
	otherMsg = []byte("other message")
)

func TestSign(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		sk, err := rsa.GenerateKey(rand.Reader, 512)
		require.NoError(t, err)

		encoded, err := keys.EncodeSecretkey(sk)
		require.NoError(t, err)

		sig, err := Sign(encoded, msg)
		require.NoError(t, err)

		pub, err := keys.ParsePublicKey(sig.PublicKey)
		require.NoError(t, err)
		h := sha256.New()
		h.Write(msg)
		d := h.Sum(nil)

		DER, _ := pem.Decode(sig.Signature)

		assert.NoError(t, rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, d, DER.Bytes))
		assert.Error(t, rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, otherMsg, DER.Bytes))
	})
	t.Run("ECDSA", func(t *testing.T) {
		sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encoded, err := keys.EncodeSecretkey(sk)
		require.NoError(t, err)

		sig, err := Sign(encoded, msg)
		require.NoError(t, err)

		pub, err := keys.ParsePublicKey(sig.PublicKey)
		require.NoError(t, err)
		h := sha256.New()
		h.Write(msg)
		d := h.Sum(nil)

		DER, _ := pem.Decode(sig.Signature)
		var ecdsaSignature struct{ R, S *big.Int }
		_, err = asn1.Unmarshal(DER.Bytes, &ecdsaSignature)
		require.NoError(t, err)
		assert.True(t, ecdsa.Verify(pub.(*ecdsa.PublicKey), d, ecdsaSignature.R, ecdsaSignature.S))
		assert.False(t, ecdsa.Verify(pub.(*ecdsa.PublicKey), d, big.NewInt(10), ecdsaSignature.S))
	})
	t.Run("ED25519", func(t *testing.T) {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		encoded, err := keys.EncodeSecretkey(sk)
		require.NoError(t, err)

		sig, err := Sign(encoded, msg)
		require.NoError(t, err)

		pub, err := keys.ParsePublicKey(sig.PublicKey)
		require.NoError(t, err)

		DER, _ := pem.Decode(sig.Signature)

		assert.True(t, ed25519.Verify(pub.(ed25519.PublicKey), sig.Message, DER.Bytes))
		assert.False(t, ed25519.Verify(pub.(ed25519.PublicKey), otherMsg, DER.Bytes))
	})
	t.Run("Bad key", func(t *testing.T) {
		_, err := Sign([]byte("test"), msg)
		require.EqualError(t, err, "failed to decode PEM block")
	})
}

func TestVerify(t *testing.T) {

	t.Run("RSA", func(t *testing.T) {

		sk, err := rsa.GenerateKey(rand.Reader, 512)
		require.NoError(t, err)

		h := sha256.New()
		h.Write(msg)
		d := h.Sum(nil)

		signature, err := rsa.SignPKCS1v15(rand.Reader, sk, crypto.SHA256, d)
		require.NoError(t, err)

		pkBytes, err := keys.EncodePublicKey(sk.Public())
		require.NoError(t, err)

		sigPEM, err := encoding.EncodePEM(signature, SignaturePEMLabel)
		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[x509.SHA256WithRSA],
			Message:   msg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[x509.SHA256WithRSA],
			Message:   otherMsg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.Error(t, err)
	})

	t.Run("ECDSA", func(t *testing.T) {
		type ecdsaSignature struct {
			R *big.Int
			S *big.Int
		}

		sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		require.NoError(t, err)

		h := sha256.New()
		h.Write(msg)
		d := h.Sum(nil)
		r, s, err := ecdsa.Sign(rand.Reader, sk, d)
		require.NoError(t, err)

		pkBytes, err := keys.EncodePublicKey(sk.Public())
		require.NoError(t, err)

		ecdsaSig := ecdsaSignature{
			R: r,
			S: s,
		}
		sigBytes, err := asn1.Marshal(ecdsaSig)
		require.NoError(t, err)
		sigPEM, err := encoding.EncodePEM(sigBytes, SignaturePEMLabel)
		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[x509.ECDSAWithSHA256],
			Message:   msg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[x509.ECDSAWithSHA256],
			Message:   otherMsg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.Error(t, err)

	})

	t.Run("ED25519", func(t *testing.T) {
		pk, sk, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signature := ed25519.Sign(sk, msg)
		pkBytes, err := keys.EncodePublicKey(pk)
		require.NoError(t, err)

		sigPEM, err := encoding.EncodePEM(signature, SignaturePEMLabel)
		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[PureED25519],
			Message:   msg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})
		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        algoName[PureED25519],
			Message:   otherMsg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.Error(t, err)
	})

	t.Run("Unsupported algorithm", func(t *testing.T) {
		pk, _, err := ed25519.GenerateKey(rand.Reader)
		pkBytes, err := keys.EncodePublicKey(pk)
		require.NoError(t, err)
		sigPEM, err := encoding.EncodePEM([]byte("test"), SignaturePEMLabel)
		require.NoError(t, err)

		err = Verify(&Signature{
			AI:        "test",
			Message:   otherMsg,
			PublicKey: pkBytes,
			Signature: sigPEM,
		})

		require.EqualError(t, err, x509.ErrUnsupportedAlgorithm.Error())

	})
}