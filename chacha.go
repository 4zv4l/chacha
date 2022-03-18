package chacha

import (
	"fmt"
	"os"
	"io"
	"strings"
	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
)

// take the input file, key and nonce in hex
// then encrypt the file in a file.cha as output
func encryptFile(in *os.File, key, nonce string) error {
	// buffer to encrypt file
	buff := make([]byte, 2048)
	// convert the key and nonce to sha256
	Key, n := sha256.Sum256([]byte(key)), sha256.Sum256([]byte(nonce))
	Nonce := n[:chacha20poly1305.NonceSizeX]
	// setup output file name
	fname := fmt.Sprintf("%s.cha", in.Name())
	out, err := os.OpenFile(fname, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil { return err }
	defer out.Close()
	stop := false
	for !stop {
		n, err := in.Read(buff)
		// check read error
		if n == 0 { break }
		if err == io.EOF { stop = true } else { return err }
		// encrypt buffer
		enc, err := encryptChaCha20(Key[:], Nonce[:], buff[:n])
		if err != nil { return err }
		_, err = out.Write(enc)
		if err != nil { return err }
	}
	return nil
}

// take the input file, key and nonce in hex
// then decrypt the file in a file.cha as output
func decryptFile(in *os.File, key, nonce string) error {
	// buffer + padding
	buff := make([]byte, 2048 + chacha20poly1305.Overhead)
	// convert the key and nonce to sha256
	Key, n := sha256.Sum256([]byte(key)), sha256.Sum256([]byte(nonce))
	Nonce := n[:chacha20poly1305.NonceSizeX]
	// setup output file name
	fname := strings.TrimSuffix(in.Name(), ".cha") + ".dec"
	out, err := os.OpenFile(fname, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil { return err }
	defer out.Close()
	stop := false
	for !stop {
		n, err := in.Read(buff)
		// check read error
		if n == 0 { break }
		if err == io.EOF { stop = true } else { return err }
		// decrypt buffer
		dec, err := decryptChaCha20(Key[:], Nonce[:], buff[:n])
		_, err = out.Write(dec)
		if err != nil { return err }
		return err
	}
	return nil
}

// decryptChaCha20 decrypt ct (cipher text)
// using the key and the nonce
func decryptChaCha20(key, nonce, ct []byte) ([]byte, error) {
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
// return the cipher text
func encryptChaCha20(key, nonce, pt []byte) ([]byte, error) {
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
