.PHONY: build run env xdpiface tear-env

generate:
	go generate ./...

build: generate
	go build -o main

run: build
	sudo ./main -linkname afxdp

