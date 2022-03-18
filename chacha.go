// Package chacha is a layer to the package golang.org/x/crypto/chacha20poly1305  
// allowing to easily encrypt/decrypt data or files
package chacha

import (
	"fmt"
	"os"
	"io"
	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
)

// Buff_size is the size of the buffer  
// it is set to 2048 bytes (2kb) by default
var Buff_size int = 2048

// take the input/output file, key and nonce in hex
// then encrypt the file and store result in the output file  
// takes care to change the nonce every time the buffer length is reached
func EncryptFile(in, out *os.File, key, nonce string) error {
	// buffer to encrypt file
	buff := make([]byte, Buff_size)
	// convert the key to sha256
	Key := sha256.Sum256([]byte(key))
	stop := false
	for !stop {
		// generate new nonce
		tmpNonce := sha256.Sum256([]byte(nonce))
		Nonce := tmpNonce[:chacha20poly1305.NonceSizeX]
		n, err := in.Read(buff)
		// check read error
		if n == 0 { break }
		if err != nil {if err == io.EOF { stop = true } else { return err }}
		// encrypt buffer
		enc, err := EncryptChaCha20(Key[:], Nonce[:], buff[:n])
		if err != nil { return err }
		_, err = out.Write(enc)
		if err != nil { return err }
	}
	return nil
}

// take the input/output file, key and nonce in hex
// then decrypt the file and store result in the output file  
// takes care to change the nonce every time the buffer length is reached
func DecryptFile(in, out *os.File, key, nonce string) error {
	// buffer + padding
	buff := make([]byte, Buff_size + chacha20poly1305.Overhead)
	// convert the key to sha256
	Key := sha256.Sum256([]byte(key))
	stop := false
	for !stop {
		// generate new nonce
		tmpNonce := sha256.Sum256([]byte(nonce))
		Nonce := tmpNonce[:chacha20poly1305.NonceSizeX]
		n, err := in.Read(buff)
		// check read error
		if n == 0 { break }
		if err != nil {if err == io.EOF { stop = true } else { return err }}
		// decrypt buffer
		dec, err := DecryptChaCha20(Key[:], Nonce[:], buff[:n])
		_, err = out.Write(dec)
		if err != nil { return err }
	}
	return nil
}

// decryptChaCha20 decrypt ct (cipher text)
// using the key and the nonce  
// return the cipher text or an error
func DecryptChaCha20(key, nonce, ct []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("cipher : %s", err)
	}
	// create buffer = cipher text - padding size
	pt := make([]byte, len(ct) - chacha20poly1305.Overhead)
	// decrypt cipher text
	pt, err = c.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// encryptChaCha20 encrypt pt (plain text)
// using the key and the nonce  
// return the cipher text or an error
func EncryptChaCha20(key, nonce, pt []byte) ([]byte, error) {
	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("encryption : %s", err)
	}
	// create buffer = plain text + padding size
	ct := make([]byte, len(pt) + chacha20poly1305.Overhead)
	// encrypt plain text
	ct = c.Seal(nil, nonce, pt, nil)
	return ct, nil
}
