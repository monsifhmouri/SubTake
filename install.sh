#!/bin/bash

echo "[+] Installing SubTake v2.0 by Mr. Monsif"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "[-] Go is not installed. Please install Go first."
    exit 1
fi

# Install dependencies
echo "[+] Installing dependencies..."
go mod tidy

# Build the tool
echo "[+] Building SubTake..."
go build -o subtake subtake.go

# Make executable
chmod +x subtake

echo "[+] Installation completed!"
echo "[+] Usage: ./subtake -f targets.txt"
echo "[+] Usage: ./subtake -d sub.example.com"