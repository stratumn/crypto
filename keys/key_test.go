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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/stratumn/go-crypto/encoding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	message = []byte("message")
)

func TestNew(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		_, priv, err := NewRSAKeyPair()
		require.NoError(t, err)
		assert.Nil(t, priv.Validate())
	})

	t.Run("ECDSA", func(t *testing.T) {
		_, _, err := NewECDSAKeyPair()
		require.NoError(t, err)
	})

	t.Run("ED25519", func(t *testing.T) {
		pub, priv, err := NewEd25519KeyPair()
		require.NoError(t, err)
		assert.Len(t, *pub.(*ed25519.PublicKey), ed25519.PublicKeySize)
		assert.Len(t, *priv, ed25519.PrivateKeySize)
	})
}

func TestGenerate(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		pub, priv, err := GenerateKey(x509.RSA)
		require.NoError(t, err)

		blockPub, _ := pem.Decode([]byte(pub))
		require.NotNil(t, blockPub)
		parsedPub, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
		require.NoError(t, err)

		blockPriv, _ := pem.Decode([]byte(priv))
		require.NotNil(t, blockPriv)
		parsedPriv, err := x509.ParsePKCS1PrivateKey(blockPriv.Bytes)
		require.NoError(t, err)

		h := sha256.New()
		h.Write(message)
		hashed := h.Sum(nil)
		sig, err := parsedPriv.Sign(rand.Reader, hashed, crypto.SHA256)
		assert.NoError(t, err)

		err = rsa.VerifyPKCS1v15(parsedPub.(*rsa.PublicKey), crypto.SHA256, hashed, sig)
		assert.NoError(t, err)
	})

	t.Run("ECDSA", func(t *testing.T) {
		pub, priv, err := GenerateKey(x509.ECDSA)
		require.NoError(t, err)

		blockPub, _ := pem.Decode([]byte(pub))
		require.NotNil(t, blockPub)
		parsedPub, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
		require.NoError(t, err)

		blockPriv, _ := pem.Decode([]byte(priv))
		require.NotNil(t, blockPriv)
		parsedPriv, err := x509.ParseECPrivateKey(blockPriv.Bytes)
		require.NoError(t, err)

		h := sha256.New()
		h.Write(message)
		hashed := h.Sum(nil)
		sig, err := parsedPriv.Sign(rand.Reader, hashed, crypto.Hash(0))
		assert.NoError(t, err)

		var sigData struct {
			R, S *big.Int
		}
		_, err = asn1.Unmarshal(sig, &sigData)
		assert.NoError(t, err)

		assert.True(t, ecdsa.Verify(parsedPub.(*ecdsa.PublicKey), hashed, sigData.R, sigData.S))
	})

	t.Run("ED25519", func(t *testing.T) {
		pub, priv, err := GenerateKey(ED25519)
		require.NoError(t, err)

		blockPub, _ := pem.Decode([]byte(pub))
		require.NotNil(t, blockPub)
		var parsedData publicKeyInfo
		_, err = asn1.Unmarshal(blockPub.Bytes, &parsedData)
		require.NoError(t, err)
		parsedPub := ed25519.PublicKey(parsedData.PublicKey.Bytes)

		blockPriv, _ := pem.Decode([]byte(priv))
		require.NotNil(t, blockPriv)
		var parsedPriv ed25519.PrivateKey
		_, err = asn1.Unmarshal(blockPriv.Bytes, &parsedPriv)
		require.NoError(t, err)

		sig, err := parsedPriv.Sign(rand.Reader, message, crypto.Hash(0))
		assert.NoError(t, err)

		assert.True(t, ed25519.Verify(parsedPub, message, sig))
	})

	t.Run("Unknown", func(t *testing.T) {
		_, _, err := GenerateKey(-1)
		require.EqualError(t, err, ErrNotImplemented.Error())
	})

}

func TestEncode(t *testing.T) {

	t.Run("RSA", func(t *testing.T) {

		pub, priv, err := NewRSAKeyPair()
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(pub)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, RSAPublicPEMLabel, block.Type)

			decoded, err := x509.ParsePKIXPublicKey(block.Bytes)
			assert.NoError(t, err)
			assert.Equal(t, pub, decoded)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(priv)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, RSASecretPEMLabel, block.Type)

			decoded, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			assert.NoError(t, err)
			assert.Equal(t, priv, decoded)
		})

	})

	t.Run("ECDSA", func(t *testing.T) {

		pub, priv, err := NewECDSAKeyPair()
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(pub)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, ECDSAPublicPEMLabel, block.Type)

			decoded, err := x509.ParsePKIXPublicKey(block.Bytes)
			assert.NoError(t, err)
			assert.Equal(t, pub, decoded)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(priv)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, ECDSASecretPEMLabel, block.Type)

			decoded, err := x509.ParseECPrivateKey(block.Bytes)
			assert.NoError(t, err)
			assert.Equal(t, priv, decoded)
		})

	})

	t.Run("ED25519", func(t *testing.T) {

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(&pub)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, ED25519PublicPEMLabel, block.Type)

			var parsedData publicKeyInfo
			_, err = asn1.Unmarshal(block.Bytes, &parsedData)
			require.NoError(t, err)
			decoded := ed25519.PublicKey(parsedData.PublicKey.Bytes)
			assert.Equal(t, pub, decoded)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(&priv)
			require.NoError(t, err)

			block, _ := pem.Decode([]byte(encoded))
			assert.NotNil(t, block)
			assert.Equal(t, ED25519SecretPEMLabel, block.Type)

			var decoded ed25519.PrivateKey
			_, err = asn1.Unmarshal(block.Bytes, &decoded)
			assert.NoError(t, err)
			assert.Equal(t, priv, decoded)
		})
	})
	t.Run("Unknown", func(t *testing.T) {
		_, err := EncodeSecretkey("bongeour")
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})

}

func TestParse(t *testing.T) {

	t.Run("RSA", func(t *testing.T) {
		pub, priv, err := NewRSAKeyPair()
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(pub)
			require.NoError(t, err)
			decodedPub, err := ParsePublicKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(priv)
			require.NoError(t, err)
			decodedPriv, decodedPub, err := ParseSecretKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
			assert.Equal(t, priv, decodedPriv)
		})
	})

	t.Run("ECDSA", func(t *testing.T) {
		pub, priv, err := NewECDSAKeyPair()
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(pub)
			require.NoError(t, err)
			decodedPub, err := ParsePublicKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(priv)
			require.NoError(t, err)
			decodedPriv, decodedPub, err := ParseSecretKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
			assert.Equal(t, priv, decodedPriv)
		})

	})

	t.Run("ED25519", func(t *testing.T) {
		pub, priv, err := NewEd25519KeyPair()
		require.NoError(t, err)

		t.Run("Public key", func(t *testing.T) {
			encoded, err := EncodePublicKey(pub)
			require.NoError(t, err)
			decodedPub, err := ParsePublicKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
		})

		t.Run("Secret key", func(t *testing.T) {
			encoded, err := EncodeSecretkey(priv)
			require.NoError(t, err)
			decodedPriv, decodedPub, err := ParseSecretKey(encoded)
			require.NoError(t, err)
			assert.Equal(t, pub, decodedPub)
			assert.Equal(t, priv, decodedPriv)
		})

	})

	t.Run("Bad format", func(t *testing.T) {
		t.Run("Not PEM", func(t *testing.T) {
			_, err := ParsePublicKey("test")
			assert.EqualError(t, err, encoding.ErrBadPEMFormat.Error())
		})
		t.Run("Unhandled public key", func(t *testing.T) {
			pub, _, _ := GenerateKey(ED25519)
			unhandledPub := strings.Replace(string(pub), "ED25519", "UNKNOWN", 2)
			_, err := ParsePublicKey(unhandledPub)
			assert.EqualError(t, err, "Could not parse public key, handled types are: ED25519 PUBLIC KEY, EC PUBLIC KEY, RSA PUBLIC KEY, PUBLIC KEY")
		})
		t.Run("Secret key", func(t *testing.T) {
			_, _, err := ParseSecretKey("test")
			assert.EqualError(t, err, encoding.ErrBadPEMFormat.Error())
		})
	})

}
