package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/JihunSKKU/HE-CCFD/lattigo_key"
)

func TestSaveKeys(t *testing.T) {
	params, btparams := initBtParams()
	// params := initParams()
	baseTime := time.Now()
	ctx := lattigo_key.NewContext(params, btparams)
	elapsedTime := time.Since(baseTime)

	fmt.Println("Make context time: ", elapsedTime)

	// SaveKeys
	err := ctx.SaveKeys("../keys")
	if err != nil {
		t.Fatalf("Failed to save keys: %v", err)
	}	
}

func TestLoadKeys(t *testing.T) {
	// TestLoadKeys tests the LoadKeys function.
	// Load Keys
	baseTime := time.Now()
	ctx, err := lattigo_key.LoadKeys("../keys")
	if err != nil {
		t.Fatalf("Failed to load Keys: %v", err)
	}
	elapsedTime := time.Since(baseTime)

	fmt.Println("Load Keys time: ", elapsedTime)

	// Check Keys
	if ctx == nil {
		t.Fatal("Keys is nil")
	}

	// Print key sizes
	ctx.PrintKeySizes()
}

