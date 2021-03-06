// Copyright 2019 Stratumn SAS. All rights reserved.
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

package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"

	"github.com/stratumn/go-crypto/aes"
	"github.com/stratumn/go-crypto/keys"
)

// Encrypt encrypt a long message with the private key.
// Only RSA keys are supported for now.
// The message is first encrypted with AES-256-GCM with a random key.
// The we encrypt the AES key with the public key.
// Returns the bytes of the ciphertext.
func Encrypt(publicKey, data []byte) ([]byte, error) {
	cipherText, aesKeyB64, err := aes.Encrypt(data)
	if err != nil {
		return nil, err
	}

	pk, _, err := keys.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	var encryptedSymKey []byte

	switch pk.(type) {
	case *rsa.PublicKey:
		encryptedSymKey, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pk.(*rsa.PublicKey), aesKeyB64, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrNotImplemented
	}

	return append(encryptedSymKey, cipherText...), nil
}

// EncryptShort encrypts a short message.
// for 2048-bit RSA keys, the max message size is 214 bytes.
// Only RSA keys are supported for now.
// The message is directly RSA-OAEP encrypted.
// Returns the bytes of the ciphertext.
func EncryptShort(publicKey, data []byte) ([]byte, error) {
	pk, _, err := keys.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	switch pk.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, pk.(*rsa.PublicKey), data, nil)
	default:
		return nil, ErrNotImplemented
	}
}
