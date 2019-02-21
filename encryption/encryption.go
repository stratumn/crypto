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

// Package encryption is used to encrypt and decrypt data using asymmetric algorithms.
// We expose methods to encrypt long messages (>256 bits) and shorts messages (<256 bits).
package encryption

import "github.com/pkg/errors"

var (
	// ErrCouldNotDecrypt is returned when the message decryption has failed for crypto reasons.
	ErrCouldNotDecrypt = errors.New("could not decrypt the message")

	// ErrNotImplemented is returned when trying to use an algo that does not handle encryption.
	ErrNotImplemented = errors.New("Unhandled encryption algorithm")
)

const (
	ivLength     = 12
	aesKeyLength = 32
)
