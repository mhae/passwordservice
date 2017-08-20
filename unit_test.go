package main

import (
	"testing"
	"time"
	"encoding/base64"
)

// Super simple unit tests ... just for illustration

func TestZeroStats(t *testing.T) {
	var pm PasswordManagerInterface = NewPasswordManager()
	r, a := pm.Stats()
	if r != 0 && a != 0 {
		t.Error("stats are not 0")
	}
}

// Verifies hash against expected value
func TestHappyPath(t *testing.T) {

	const expected = "ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q=="

	var pm PasswordManagerInterface = NewPasswordManager()
	id := pm.Hash("angryMonkey")
	if id != 0 {
		t.Error("id is not 0")
	}

	if ! pm.HasPendingHashes() {
		t.Error("no pending hashes")
	}

	var pwdHash []byte = nil
	ts := time.Now()
	for {
		pwdHash = pm.Get(id)
		if pwdHash != nil {
			encoded := base64.StdEncoding.EncodeToString(pwdHash)
			if encoded != expected {
				t.Error("hash mismatch")
			} else {
				break
			}
		}

		time.Sleep(1*time.Second)

		if time.Now().Sub(ts).Seconds() > 10 {
			t.Error("hash didn't complete in time")
			break
		}
	}

	if pm.HasPendingHashes() {
		t.Error("mgr still has pending hashes")
	}
}

