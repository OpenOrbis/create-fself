#!/bin/bash -v
cd ../cmd/create-fself

# Init
#go mod init github.com/OpenOrbis/create-fself

## Windows
GOOS=windows go build -o create-fself.exe -modfile=go-linux.mod
mv ./create-fself.exe ${OO_PS4_TOOLCHAIN}/bin/windows/create-fself.exe

## Linux
go build -o create-fself -modfile=go-linux.mod
mv ./create-fself ${OO_PS4_TOOLCHAIN}/bin/linux/create-fself

## MacOS
GOOS=darwin GOARCH=amd64 go build -o create-fselfosx -modfile=go-linux.mod
mv ./create-fselfosx ${OO_PS4_TOOLCHAIN}/bin/macos/create-fself
