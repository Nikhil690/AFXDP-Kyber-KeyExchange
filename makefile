.PHONY: build run

generate:
	go generate ./...

build: generate
	go build -o test

run: build
	./main