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
	"encoding/asn1"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodePEM(t *testing.T) {

	test, err := asn1.Marshal(struct{ Test []byte }{[]byte("test")})
	require.NoError(t, err)
	label := "label"

	t.Run("Writes bytes to the PEM format", func(t *testing.T) {
		data, err := EncodePEM(test, label)
		require.NoError(t, err)

		block, _ := pem.Decode(data)
		assert.Equal(t, block.Bytes, test)
		assert.Equal(t, block.Type, label)
	})

	t.Run("Handles null input", func(t *testing.T) {
		data, err := EncodePEM(nil, label)
		require.NoError(t, err)
		block, _ := pem.Decode(data)
		assert.Equal(t, block.Type, label)
	})
}

func TestDecodePEM(t *testing.T) {
	test, err := asn1.Marshal(struct{ Test []byte }{[]byte("test")})
	require.NoError(t, err)
	label := "label"

	t.Run("Decode bytes from the PEM format", func(t *testing.T) {
		var b bytes.Buffer
		pem.Encode(&b, &pem.Block{Type: label, Bytes: test})

		decoded, err := DecodePEM(b.Bytes(), label)
		require.NoError(t, err)
		assert.Equal(t, decoded, test)
	})

	t.Run("Fails when labels don't match", func(t *testing.T) {
		var b bytes.Buffer
		pem.Encode(&b, &pem.Block{Type: label, Bytes: test})

		_, err := DecodePEM(b.Bytes(), "other")
		require.EqualError(t, err, "Wrong PEM block type: want other, got label")
	})
}
