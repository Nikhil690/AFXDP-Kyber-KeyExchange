.PHONY: build run

generate:
	go generate ./...

build: generate
	go build -o main

run: build
	sudo ./main -linkname afxdp