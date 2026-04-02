// Package stepca — JWE decryption for step-ca provisioner keys.
//
// step-ca stores provisioner private keys as JWE-encrypted JSON files using:
//   - Algorithm: PBES2-HS256+A128KW (PBKDF2 key derivation + AES-128 Key Wrap)
//   - Encryption: A128GCM (AES-128 in GCM mode)
//
// This file implements just enough JWE to decrypt these files without requiring
// an external JOSE library. Uses only stdlib + golang.org/x/crypto/pbkdf2.
package stepca

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// jweJSON is the JWE JSON Serialization format used by step-ca provisioner keys.
type jweJSON struct {
	Protected    string `json:"protected"`
	EncryptedKey string `json:"encrypted_key"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
	Tag          string `json:"tag"`
}

// jweHeader is the protected header inside a step-ca provisioner key JWE.
type jweHeader struct {
	Alg string `json:"alg"` // "PBES2-HS256+A128KW"
	Enc string `json:"enc"` // "A128GCM"
	Cty string `json:"cty"` // "jwk+json"
	P2s string `json:"p2s"` // PBKDF2 salt (base64url)
	P2c int    `json:"p2c"` // PBKDF2 iteration count
}

// jwkEC is a minimal JWK representation for EC private keys.
type jwkEC struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	Kid string `json:"kid"`
}

// decryptProvisionerKey decrypts a step-ca JWE-encrypted provisioner key file.
// Returns the parsed ECDSA private key and the key ID (kid).
func decryptProvisionerKey(jweData []byte, password string) (*ecdsa.PrivateKey, string, error) {
	// Parse JWE JSON
	var jwe jweJSON
	if err := json.Unmarshal(jweData, &jwe); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWE JSON: %w", err)
	}

	// Decode protected header
	headerBytes, err := base64.RawURLEncoding.DecodeString(jwe.Protected)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode JWE protected header: %w", err)
	}

	var header jweHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, "", fmt.Errorf("failed to parse JWE header: %w", err)
	}

	if header.Alg != "PBES2-HS256+A128KW" {
		return nil, "", fmt.Errorf("unsupported JWE algorithm: %s (expected PBES2-HS256+A128KW)", header.Alg)
	}
	if header.Enc != "A128GCM" && header.Enc != "A256GCM" {
		return nil, "", fmt.Errorf("unsupported JWE encryption: %s (expected A128GCM or A256GCM)", header.Enc)
	}

	// Decode PBKDF2 salt
	p2sSalt, err := base64.RawURLEncoding.DecodeString(header.P2s)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode PBKDF2 salt: %w", err)
	}

	// Decode encrypted key, IV, ciphertext, tag
	encryptedKey, err := base64.RawURLEncoding.DecodeString(jwe.EncryptedKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	iv, err := base64.RawURLEncoding.DecodeString(jwe.IV)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode IV: %w", err)
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(jwe.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	tag, err := base64.RawURLEncoding.DecodeString(jwe.Tag)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode tag: %w", err)
	}

	// Step 1: Derive Key Encryption Key (KEK) using PBKDF2
	// PBES2-HS256+A128KW: PBKDF2-SHA256, 16-byte derived key for AES-128 Key Wrap
	// The salt for PBKDF2 is: UTF8(alg) || 0x00 || p2s
	algBytes := []byte(header.Alg)
	salt := make([]byte, len(algBytes)+1+len(p2sSalt))
	copy(salt, algBytes)
	salt[len(algBytes)] = 0x00
	copy(salt[len(algBytes)+1:], p2sSalt)

	kekSize := 16 // AES-128 for A128KW
	kek := pbkdf2.Key([]byte(password), salt, header.P2c, kekSize, sha256.New)

	// Step 2: AES Key Unwrap (RFC 3394) to get the Content Encryption Key (CEK)
	cek, err := aesKeyUnwrap(kek, encryptedKey)
	if err != nil {
		return nil, "", fmt.Errorf("AES key unwrap failed (wrong password?): %w", err)
	}

	// Step 3: AES-GCM decrypt the payload
	// AAD = ASCII(BASE64URL(protected header))
	aad := []byte(jwe.Protected)

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// GCM expects ciphertext+tag concatenated
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, aad)
	if err != nil {
		return nil, "", fmt.Errorf("GCM decryption failed: %w", err)
	}

	// Step 4: Parse the decrypted JWK
	var jwk jwkEC
	if err := json.Unmarshal(plaintext, &jwk); err != nil {
		return nil, "", fmt.Errorf("failed to parse decrypted JWK: %w", err)
	}

	if jwk.Kty != "EC" {
		return nil, "", fmt.Errorf("unsupported JWK key type: %s (expected EC)", jwk.Kty)
	}

	key, err := jwkToECDSA(&jwk)
	if err != nil {
		return nil, "", err
	}

	return key, jwk.Kid, nil
}

// jwkToECDSA converts a JWK EC key to an *ecdsa.PrivateKey.
func jwkToECDSA(jwk *jwkEC) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK y: %w", err)
	}
	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWK d: %w", err)
	}

	key := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		},
		D: new(big.Int).SetBytes(dBytes),
	}

	return key, nil
}

// aesKeyUnwrap implements AES Key Unwrap per RFC 3394.
func aesKeyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%8 != 0 || len(ciphertext) < 24 {
		return nil, fmt.Errorf("invalid ciphertext length for AES Key Unwrap: %d", len(ciphertext))
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	n := (len(ciphertext) / 8) - 1 // number of 64-bit key data blocks

	// Initialize
	a := make([]byte, 8)
	copy(a, ciphertext[:8])

	r := make([][]byte, n)
	for i := 0; i < n; i++ {
		r[i] = make([]byte, 8)
		copy(r[i], ciphertext[(i+1)*8:(i+2)*8])
	}

	// Unwrap: 6 rounds
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// A ^= (n*j + i) encoded as big-endian uint64
			t := uint64(n*j + i)
			tBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(tBytes, t)
			for k := 0; k < 8; k++ {
				a[k] ^= tBytes[k]
			}

			// B = AES-1(KEK, A || R[i])
			copy(buf[:8], a)
			copy(buf[8:], r[i-1])
			block.Decrypt(buf, buf)

			copy(a, buf[:8])
			copy(r[i-1], buf[8:])
		}
	}

	// Check the integrity check value (must be 0xA6A6A6A6A6A6A6A6)
	defaultIV := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	for i := 0; i < 8; i++ {
		if a[i] != defaultIV[i] {
			return nil, fmt.Errorf("AES Key Unwrap integrity check failed")
		}
	}

	// Concatenate unwrapped key data
	result := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		result = append(result, r[i]...)
	}

	return result, nil
}
