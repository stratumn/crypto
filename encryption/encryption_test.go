package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stratumn/go-crypto/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
)

var (
	message = []byte("coucou, tu veux voir mon message ?")

	rsaSk = []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDBsNAxEZ0pqCJq\nmFfADdx20uxx74kCFVI38QC0tPQGeaPIiL4z5/gCRzsWLhrUUCal83oaYKONmWcr\nF0z7+nXm+szjXq7Mp6G43VYVpZNxvBAqPg94e6AdKqtuZn+XRCLZhoSpefUqkJzB\nfze37Eohb7wf/JFutNweEmzpg77EL0D/RsBAuBnDJyvWeATaFB53Ip1SEBlIHyPH\n0Io0FXPLZS3TR4SKWykaekNubLZe9itNn5S1RPHLbK+Hz9f9BowMnEriOziOZa4A\ndhqnHw7ukWo08VkyJsVRwdvccwYz9QPeCtk0rXyubgWKQ1n/26XU7tyXT8qj0BQ7\nBWkMQaPRAgMBAAECggEBAJ85bfxYgX1EJX7BW6ma+3iG7i6/fj7DLkKkkTL8anqE\nNnrcxpc/A2dEDTOvlQiiFxNnMyJJ/UmjKOeIkRW3kILf+9yR8lp1F4I0GddTtQDT\nW+qN+APQhRBVCnaINi0wqwFtDtOPWVazaNm8bh55VXtlMh6NbzS14xmphfT1A7ab\nvn5be3L5FzRQEIhai6Uqc2SY3iAfc+honElnYwL0ND7hoU+wJgs8Btvb2Um3fMA5\n4WDM0tSrLCnGMzCjn9PuROQav0F8nEqq3/zAEB1UBCjNitUnjGUDNGsWM4/GtWDs\nR12H0Vg9Pb4nfnPPfD8PWUuTNhD/RTzeP73BS1SaJcECgYEA8oI8DtZFEsNXfeq7\nqw079+FAWjB14HXwyhZsl2Qd8jlahpRfUH0HUGsHBT4bydYtfvyJ2yjza/fhZdZC\nk1wTPGp84y5WAvGqkYAsPDbM3Fez7O1PQ4ZJw7JYW/mjo2r+3KYKLixshVaWDcAC\nF5J10cp6R8DEMejBs9VKSwhJDFkCgYEAzHdSH0J3MtKY36B2iwBFn5fTeKyFhLsQ\n7dVG8R+22Sd17rNtUeG0yn4RFK36GRLgPl4kRYlrfLBiXbVqdtBfUaffvoteTv6k\n++86KQjSo7veUCsRkT9HSB4+G7vQ59v3IqwYpCbFe5iwgufCPsVJskBnfMAhNqni\nxFYB2yKghDkCgYEA45isyvP34bMpcsiRluiVxn9FyR9AEgg+kztWcQMKQ+Hl/vZT\nOhQNgEDiVt5CcDwteMeEjgYx5ru+c7gRxYEdoI8EZKaBHMQ4Y9PaMCzyOT2qZIsX\n3/SxWBQSb0esd1uck/LVDR6uPrnTnFX+4KaZIuqXtq3ItFqRKLjdv+unuwkCgYBk\nwK9g4/mku43FNGb1m86zE7eLEUhB3YQ8DgqFKuGJJB7C3vuRi6zw0ypLjGdfD6Qc\nV3t8IHks2iW+k3TA03EE5bolRLvWJTjbREjei5BwSlUEIBTqA8p2SSDFvcj1V7jy\nBueli81oWBcyik13bPQhuAbGvE4hh5lMsiz79JYwUQKBgQDTwiOYbrrB/zNS6VdP\nn8Q0GxDbvDQRd0JjCp7aw4cX9g+gvsX9CETocAPQXpBD+f/6+Y5pvJN8BoZKdSqF\nHDIuKefy+M1zAbIbFLmWBNQZCUlq57jOZ/1BG3Y/qO3FD869ltwA/lYjUYv2pfGY\nRLJR2hWagXEb4vUCyY/Hhplv5A==\n-----END RSA PRIVATE KEY-----\n")
	rsaPk = []byte("-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwbDQMRGdKagiaphXwA3c\ndtLsce+JAhVSN/EAtLT0BnmjyIi+M+f4Akc7Fi4a1FAmpfN6GmCjjZlnKxdM+/p1\n5vrM416uzKehuN1WFaWTcbwQKj4PeHugHSqrbmZ/l0Qi2YaEqXn1KpCcwX83t+xK\nIW+8H/yRbrTcHhJs6YO+xC9A/0bAQLgZwycr1ngE2hQedyKdUhAZSB8jx9CKNBVz\ny2Ut00eEilspGnpDbmy2XvYrTZ+UtUTxy2yvh8/X/QaMDJxK4js4jmWuAHYapx8O\n7pFqNPFZMibFUcHb3HMGM/UD3grZNK18rm4FikNZ/9ul1O7cl0/Ko9AUOwVpDEGj\n0QIDAQAB\n-----END RSA PUBLIC KEY-----\n")
)

func TestDecrypt(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		ciphertext, _ := base64.StdEncoding.DecodeString("N1TWMI4rpB9YBQCO3V0BkHIVW7Q0Z+Bh3A8qiHXPGKkWA34HNiWdb1jqqyjIy5QamWZjJFTs8Hvt3o2YLEbf3/KIvZs1rajuVP/jvU1OlQ7oFlmqKdtuFMnIJhTavmFMDtAujzotZOb7Foogqh7PE7Ud0u9NBl3OKIWTrj2YUg+lRs1k7RGN9oi786ITd6UATcQ7CWA58QIv6uzNaMeIVKJEwdemiKZ9mxMQlCtErcgP3yBBTECwHQj0qJeYlqIz8nC4Bmk7WzlKJtaZyvvoXeBqem8o7TVo3ZbWs9+3pDMwMQkIvh12jJj2LRhohtgpYVJjiiWnZmfwjmf1+uQgMTvOug6PzYb1UTJzYc0pXY2o756GEMkTpK+wmzXgn2jwEzf772eVZS15FlSeHJcvHMxuPakXE+pLN117X8p/")

		pt, err := Decrypt(rsaSk, ciphertext)
		require.NoError(t, err)

		assert.Equal(t, message, pt)
	})

	t.Run("ECDSA", func(t *testing.T) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		encoded, _ := keys.EncodeSecretkey(sk)

		_, err := Decrypt(encoded, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})

	t.Run("ED25519", func(t *testing.T) {
		_, sk, _ := ed25519.GenerateKey(rand.Reader)
		encoded, _ := keys.EncodeSecretkey(&sk)

		_, err := Decrypt(encoded, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})
}

func TestDecryptShort(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		shortCiphertext, _ := base64.StdEncoding.DecodeString("A9ZtekEBvZBbxsLG36C8Nc0RLMPQL6uDhZ+E7bRGiQBgW9MdyI5niizNRCgx71OxQEuMGYWGuFrvTnP79sJ3z8PEq3OneYrmghU+dw5BfrvsXpvOkw4SUulV5EnwjrAvLvWtfkAelVQWsYte/xalSMv4NHMitui1SD/SUQnqg64u/afp53z5PRXKW5VOVl5yrprXOJ2KL6rTxijz/m3DLOefGzaFhW4LgYLjaebZ1upHEci8h6Mz/KI2GyciNAM+bt7FtEEntX8PRJVuIKPbds3arIUQBaYbBVt3QKqbd7KhHfwfw8sRT28O0wapz8KPNaOWmWKDDusz7NtKf52Phg==")

		pt, err := DecryptShort(rsaSk, shortCiphertext)
		require.NoError(t, err)

		assert.Equal(t, message, pt)
	})

	t.Run("ECDSA", func(t *testing.T) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		encoded, _ := keys.EncodeSecretkey(sk)

		_, err := DecryptShort(encoded, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})

	t.Run("ED25519", func(t *testing.T) {
		_, sk, _ := ed25519.GenerateKey(rand.Reader)
		encoded, _ := keys.EncodeSecretkey(&sk)

		_, err := DecryptShort(encoded, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		ct, err := Encrypt(rsaPk, message)
		require.NoError(t, err)

		pt, err := Decrypt(rsaSk, ct)
		require.NoError(t, err)

		assert.Equal(t, message, pt)
	})

	t.Run("ECDSA", func(t *testing.T) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes, _ := keys.EncodePublicKey(sk.Public())

		_, err := Encrypt(pkBytes, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})

	t.Run("ED25519", func(t *testing.T) {
		pk, _, _ := ed25519.GenerateKey(rand.Reader)
		pkBytes, _ := keys.EncodePublicKey(&pk)

		_, err := Encrypt(pkBytes, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})
}

func TestEncryptShort(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		ct, err := EncryptShort(rsaPk, message)
		require.NoError(t, err)

		pt, err := DecryptShort(rsaSk, ct)
		require.NoError(t, err)

		assert.Equal(t, message, pt)
	})

	t.Run("ECDSA", func(t *testing.T) {
		sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pkBytes, _ := keys.EncodePublicKey(sk.Public())

		_, err := EncryptShort(pkBytes, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})

	t.Run("ED25519", func(t *testing.T) {
		pk, _, _ := ed25519.GenerateKey(rand.Reader)
		pkBytes, _ := keys.EncodePublicKey(&pk)

		_, err := EncryptShort(pkBytes, []byte("123"))
		assert.EqualError(t, err, ErrNotImplemented.Error())
	})
}
