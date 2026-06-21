package main

import (
	"flag"
	"fmt"
	"os"

	"xconf-agent/config"
	"xconf-agent/crypto"
)

func runDecrypt(args []string) {
	fmt.Println("[WARNING]")
	fmt.Println("    Configuration recovery (restore) involves network state reloading and carries a risk of network interruption. Please ensure you verify the completeness of this configuration in an offline/test environment before applying it. The service provider assumes no responsibility for any network outage caused by recovery operations.")
	fmt.Println()

	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to the encrypted .raw.enc backup file")
	key := fs.String("key", "", "Hex-encoded AGENT_KEY")
	outPath := fs.String("out", "", "Path to write the decrypted plaintext (optional, prints to stdout if omitted)")

	_ = fs.Parse(args)

	if *filePath == "" {
		fmt.Println("Error: --file is required")
		fs.Usage()
		os.Exit(1)
	}
	if *key == "" {
		fmt.Println("Error: --key is required")
		fs.Usage()
		os.Exit(1)
	}

	// Validate Key
	rawKey, err := config.ValidateKey(*key)
	if err != nil {
		fmt.Printf("Error: Invalid AGENT_KEY: %v\n", err)
		os.Exit(1)
	}

	// Read ciphertext
	packet, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("Error: Failed to read file %s: %v\n", *filePath, err)
		os.Exit(1)
	}

	// Decrypt
	plaintext, err := crypto.DecryptConfig(packet, rawKey)
	if err != nil {
		fmt.Printf("Error: Decryption failed: %v\n", err)
		fmt.Println("Hint: Please check that the key matches the one used to encrypt the backup, and that the file is not corrupted.")
		os.Exit(1)
	}

	if *outPath != "" {
		err = os.WriteFile(*outPath, plaintext, 0600)
		if err != nil {
			fmt.Printf("Error: Failed to write output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Decrypted config written to: %s\n", *outPath)
	} else {
		fmt.Println("--- Decrypted Config Output ---")
		fmt.Println(string(plaintext))
		fmt.Println("-------------------------------")
	}
}
