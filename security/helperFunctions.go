package security

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
)

// Decode base64 string → plain text
func DecryptBase64(base64String string) (string, error) {
	// Step 1: decode base64
	decoded, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Check gzip magic header: 0x1f 0x8b
	if len(decoded) > 2 && decoded[0] == 0x1f && decoded[1] == 0x8b {
		reader, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			return "", fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer reader.Close()

		unzipped, err := io.ReadAll(reader)
		if err != nil {
			return "", fmt.Errorf("failed to read gzip data: %w", err)
		}
		return string(unzipped), nil
	}

	// Otherwise treat as plain text
	return string(decoded), nil
}

// Encode plain text → base64 string
func EncryptBase64(data string) (string, error) {
	var buf bytes.Buffer

	// gzip compress
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write([]byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to write gzip data: %w", err)
	}
	writer.Close()

	// base64 encode
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
