package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

type Crypto struct{}

func (c *Crypto) AesEncrypt(message string, cryptoKey []byte, iv []byte, check bool) string {
	paddedMessage := c.pad([]byte(message), aes.BlockSize)

	block, _ := aes.NewCipher(cryptoKey)
	cipherText := make([]byte, len(paddedMessage))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedMessage)

	encodedMessage := base64.StdEncoding.EncodeToString(cipherText)

	return encodedMessage
}

func (c *Crypto) AesDecrypt(cryptoKey []byte, iv []byte, encodedMessage string) string {
	decodedMessage, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		return encodedMessage
	}

	block, _ := aes.NewCipher(cryptoKey)
	decryptedMessage := make([]byte, len(decodedMessage))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decryptedMessage, decodedMessage)

	unpaddedMessage := c.unpad(decryptedMessage)

	return string(unpaddedMessage)
}

func (c *Crypto) pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	paddingStr := strings.Repeat(string(rune(padding)), padding)
	paddedData := append(data, []byte(paddingStr)...)

	return paddedData
}

func (c *Crypto) unpad(data []byte) []byte {
	padding := int(data[len(data)-1])

	if padding < 1 || padding > len(data) {
		return data
	}

	isPaddingValid := regexp.MustCompile(fmt.Sprintf("^%d{%d}$", padding, padding))
	if !isPaddingValid.Match(data[len(data)-padding:]) {
		return data
	}

	return data[:len(data)-padding]
}
