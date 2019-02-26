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

// Package aes is used to encrypt and decrypt data using symmetric algorithms.
// The algorithm used is AES-256-GCM.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"github.com/pkg/errors"
)

var (
	// ErrCouldNotDecrypt is returned when the message decryption has failed for crypto reasons.
	ErrCouldNotDecrypt = errors.New("could not decrypt the message")
)

const (
	// IVLength is the length of the IV.
	IVLength = 12
	// KeyLength is the length of the key.
	KeyLength = 32
)

// Encrypt encrypts a message with AES-256-GCM with a random key.
// Returns the bytes of the ciphertext and the bytes of the base64-encoded AES key.
// The key is base64 exported to follow the pattern chosen in @stratumn/js-crypto...
func Encrypt(data []byte) ([]byte, []byte, error) {
	// Generate a random 256-bit key.
	key := make([]byte, KeyLength)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the message with AES-256-GCM.
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, IVLength)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, iv, data, nil)
	if err != nil {
		return nil, nil, err
	}

	b64Key := []byte(base64.StdEncoding.EncodeToString(key))
	return append(iv, ciphertext...), b64Key, nil
}

// Decrypt decrypts message encrypted with AES-256-GCM.
// The key is base64 encoded.
// Returns the bytes of the plaintext.
func Decrypt(data, b64Key []byte) ([]byte, error) {
	// The decrypted AES key is base64 encoded, we have to decode it.
	key, err := base64.StdEncoding.DecodeString(string(b64Key))
	if err != nil {
		return nil, ErrCouldNotDecrypt
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCouldNotDecrypt
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, ErrCouldNotDecrypt
	}

	iv := data[0:IVLength]
	msg := data[IVLength:]

	res, err := gcm.Open(nil, iv, msg, nil)
	if err != nil {
		return nil, ErrCouldNotDecrypt
	}

	return res, nil
}
