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

package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	"github.com/stratumn/go-crypto/keys"
)

// Encrypt encrypt a long message with the private key.
// Only RSA keys are supported for now.
// The message is first encrypted with AES-256-GCM with a random key.
// The we encrypt the AES key with the public key.
// Returns the bytes of the ciphertext.
func Encrypt(publicKey, data []byte) ([]byte, error) {

	// Generate a random 256-bit key.
	aesKey := make([]byte, aesKeyLength)
	_, err := rand.Read(aesKey)
	if err != nil {
		return nil, err
	}

	// Encrypt the message with AES-256-GCM.
	c, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(c, tagLength)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, ivLength)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, iv, data, nil)
	if err != nil {
		return nil, err
	}

	pk, _, err := keys.ParsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	// We encrypt the base64 encoding of the AES key...
	// Same thing is done in @stratumn/js-crypto
	aesKeyB64 := []byte(base64.StdEncoding.EncodeToString(aesKey))
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

	res := append(encryptedSymKey, iv...)
	res = append(res, ciphertext...)

	return res, nil
}

// EncryptShort encrypts a short message.
// for 2048-bit RSA keys, the max message size is 214 bytes.
// Only RSA keys are supported for now.
// The message is directly RSA-OAEP encrypted.
// Returns the bytes of the ciphertext.
func EncryptShort(publicKey, data []byte) ([]byte, error) {
	pk, _, err := keys.ParsePublicKey(publicKey)
	if err != nil {
		fmt.Println("============================")
		return nil, err
	}

	switch pk.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha1.New(), rand.Reader, pk.(*rsa.PublicKey), data, nil)
	default:
		return nil, ErrNotImplemented
	}
}
