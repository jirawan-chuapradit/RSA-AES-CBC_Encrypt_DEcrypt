package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"reflect"
	"testing"
)

func TestDecryptOAEP(t *testing.T) {
	type args struct {
		hash       hash.Hash
		privateKey *rsa.PrivateKey
		msg        []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptOAEP(tt.args.hash, tt.args.privateKey, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptOAEP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecryptOAEP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkDecryptOAEP(b *testing.B) {
	hash := sha256.New()
	privateKey, err := GetKeys()
	if err != nil {
		fmt.Println("Could not retrieve key file", err)
		return
	}

	m1 := generateMockData(privateKey)
	byt, _ := json.Marshal(m1)
	encryptedBytes, err := EncryptOAEP(hash, &privateKey.PublicKey, byt)
	if err != nil {
		fmt.Println("Could encrypt OAEP", err)
		return
	}
	// run the DecryptOAEP function b.N times
	for n := 0; n < b.N; n++ {
		DecryptOAEP(hash, privateKey, encryptedBytes)
	}
}
