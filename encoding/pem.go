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

package encoding

import (
	"bytes"
	"encoding/pem"

	"github.com/pkg/errors"
)

// ErrBadPEMFormat is the error returned when a parsing error occured while trying to decode a PEM block.
var ErrBadPEMFormat = errors.New("failed to decode PEM block")

// EncodePEM serializes any data to the PEM format.
func EncodePEM(val []byte, label string) (string, error) {
	var b bytes.Buffer
	if err := pem.Encode(&b, &pem.Block{Type: label, Bytes: val}); err != nil {
		return "", err
	}

	return b.String(), nil
}

// DecodePEM deserializes a PEM block and returns the bytes contained in it.
func DecodePEM(data string, label string) ([]byte, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, ErrBadPEMFormat
	}

	if label != "" && block.Type != label {
		return nil, errors.Errorf("Wrong PEM block type: want %s, got %s", label, block.Type)
	}
	return block.Bytes, nil
}
