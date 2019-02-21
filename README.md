# GO-CRYPTO

This library contains tools to manipulate keys and signatures.

The key algorithms currently handled are: `RSA`, `ECDSA` and `ED25519`.

The signature algorithms currently handled are `RSA-SHA256`, `ECDSA-SHA256` and `ED25519`

The code is splitted in 3 packages :

## keys

This package lets you generate, encode and decode keys:

```golang
import (
    "github.com/stratumn/go-crypto/keys"
    "crypto/x509"
)

func main() {
    pub, priv, err := keys.GenerateKey(x509.RSA) // use x509.RSA, x509.ECDSA or keys.ED25519
    fmt.Println(string(priv))
//-----BEGIN RSA PRIVATE KEY-----
// MIIJKgIBAAKCAgEAySIguzsYqm4p+I5/DU0dkUasSHhzc0xPQsjBeR1/iNAoZP4n
// /R6hwiAY5r8C98Qgnf3CVvgB47Wpof8iBRvN1FX/PTa7KJB/lTDrEeRLnS7dRUqy
// ...
//-----END RSA PRIVATE KEY-----

    // you can parse it to retrieve the go type..
    parsedPub, err := keys.ParsePublicKey(pub)
    parsedPriv, err := keys.ParseSecretKey(priv)

    // ...and encode the native type to a PEM string containing the ASN.1 DER encoding of the public/secret key
    encodedPub, err := keys.ParsePublicKey(pub)
    encodedPriv, err := keys.ParseSecretKey(priv)

    fmt.Println(string(encodedPriv))
//-----BEGIN RSA PRIVATE KEY-----
// MIIJKgIBAAKCAgEAySIguzsYqm4p+I5/DU0dkUasSHhzc0xPQsjBeR1/iNAoZP4n
// /R6hwiAY5r8C98Qgnf3CVvgB47Wpof8iBRvN1FX/PTa7KJB/lTDrEeRLnS7dRUqy
// ...
//-----END RSA PRIVATE KEY-----
}
```

## signatures

This package lets you sign messages and verify signatures:

```golang
import (
    "github.com/stratumn/go-crypto/signatures"
    "github.com/stratumn/go-crypto/keys"
    "crypto/x509"
)

func main() {
    pub, priv, err := keys.GenerateKey(keys.ED25519)
    fmt.Println(string(priv))
// -----BEGIN ED25519 PRIVATE KEY-----
// MIIJKgIBAAKCAgEAySIguzsYqm4p+I5/DU0dkUasSHhzc0xPQsjBeR1/iNAoZP4n
// ...
// -----END ED25519 PRIVATE KEY-----

    // let's sign a messae
    message := "message"
    signature, err := signatures.Sign(priv, message)
    fmt.Println(string(signature.Signature))
// -----BEGIN MESSAGE-----
// jj4g5RphoN3lYRlIE9joL/DJx15g4EWKODflq8j52oPhmjJU70vTmxlKxBBUdo1h
// rPZdJFvy/biqr80NEs/TcwFt29k9dqsADpDIENCR1zuieUKM5T7nXxyIuF6G7fZc
// njNBXKge+iDbVR6u+jicO5MKWH1P46dq5Zlfddy81+yuEsmCQblZYYWqAbgOmRPm
// -----END MESSAGE----

    // verify that the signature is valid
    err := signatures.Verify(signature)
    if err != nil {
        panic("signature verification failed !")
    }
}
```

## encoding

This package provides utility functions to encode and decode data using PEM format

```golang
import (
    "github.com/stratumn/go-crypto/encoding"
    "crypto/x509"
)

func main() {
    // encode some data with a label
    data := []byte("my data")
    pem, err := encoding.EncodePEM(data, "label")
    fmt.Println(string(pem))
// -----BEGIN label-----
// Ft29k9dqsA
// -----END label-----

    // you can decode data the same way
    // you can chose to pass a label if you want to check that it matches
    // if you pass an empty label, the body will be decoded without checking the header
    decoded, err := encoding.DecodePEM(pem, "label")
    if err != nil {
        panic("PEM labels do not match")
    }
    fmt.Println(string(decoded))
// my data
}
```

## encryption

This package lets you encrypt and decrypt messages. For now, only RSA keys are supported.
We expose two different encryption schemes:

- RSA-OAEP + AES-GCM to encrypt any size of message. The message is encrypted using a symmetric AES-GCM-256 key,
  and that key is in turn encrypted using RSA-OAEP

```golang
import (
	"crypto/x509"
	"fmt"

	"github.com/stratumn/go-crypto/encryption"
	"github.com/stratumn/go-crypto/keys"
)

func main() {
	pub, priv, err := keys.GenerateKey(x509.RSA)
	fmt.Println(string(priv))
	// -----BEGIN ED25519 PRIVATE KEY-----
	// MIIJKgIBAAKCAgEAySIguzsYqm4p+I5/DU0dkUasSHhzc0xPQsjBeR1/iNAoZP4n
	// ...
	// -----END ED25519 PRIVATE KEY-----

	// let's sign a messae
	message := []byte("a very secret message")
	ciphertext, err := encryption.Encrypt(pub, message)

	// verify that the signature is valid
	plaintext, err := encryption.Decrypt(priv, ciphertext)
	if err != nil {
		panic("decryption failed !")
	}

	fmt.Println(string(plaintext))
	// a very secret message
}
```

- RSA-OAEP to encrypt short messages. The message is directly encrypted using the asymmetric algo.
  The message size should be limited to keyLenBits / 8 - 42 = 214 bytes for 2048 RSA keys.

```golang
import (
	"crypto/x509"
	"fmt"

	"github.com/stratumn/go-crypto/encryption"
	"github.com/stratumn/go-crypto/keys"
)

func main() {
	pub, priv, err := keys.GenerateKey(x509.RSA)
	fmt.Println(string(priv))
	// -----BEGIN ED25519 PRIVATE KEY-----
	// MIIJKgIBAAKCAgEAySIguzsYqm4p+I5/DU0dkUasSHhzc0xPQsjBeR1/iNAoZP4n
	// ...
	// -----END ED25519 PRIVATE KEY-----

	// let's sign a messae
	message := []byte("a very secret message")
	ciphertext, err := encryption.EncryptShort(pub, message)

	// verify that the signature is valid
	plaintext, err := encryption.DecryptShort(priv, ciphertext)
	if err != nil {
		panic("decryption failed !")
	}

	fmt.Println(string(plaintext))
	// a very secret message
}
```
