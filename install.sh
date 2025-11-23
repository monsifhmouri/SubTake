#!/bin/bash

echo "[+] Installing SubTake v2.0 by Mr. Monsif"

if ! command -v go &> /dev/null; then
    echo "[-] Go is not installed. Please install Go first."
    exit 1
fi

echo "[+] Installing dependencies..."
go mod tidy

echo "[+] Building SubTake..."
go build -o subtake subtake.go

chmod +x subtake

echo "[+] Installation completed!"
echo "[+] Usage: ./subtake -f targets.txt"
echo "[+] Usage: ./subtake -d sub.example.com"
