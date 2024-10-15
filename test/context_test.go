package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/JihunSKKU/HE-CCFD/lattigo_key"
)

func TestSaveContext(t *testing.T) {
	// TestSaveContext tests the SaveContext function.
	params, btparams := initBtParams()
	// params := initParams()
	baseTime := time.Now()
	ctx := lattigo_key.NewContext(params, btparams)
	elapsedTime := time.Since(baseTime)

	fmt.Println("Make context time: ", elapsedTime)

	// Save context
	err := ctx.SaveContext("../context/ctx")
	if err != nil {
		t.Fatalf("Failed to save context: %v", err)
	}	
}

func TestLoadContext(t *testing.T) {
	// TestLoadContext tests the LoadContext function.
	// Load context
	baseTime := time.Now()
	ctx, err := lattigo_key.LoadContext("../context/serialized_ctx")
	if err != nil {
		t.Fatalf("Failed to load context: %v", err)
	}
	elapsedTime := time.Since(baseTime)

	fmt.Println("Load context time: ", elapsedTime)

	// Check context
	if ctx == nil {
		t.Fatal("Context is nil")
	}

	// Print key sizes
	ctx.PrintKeySizes()
}

