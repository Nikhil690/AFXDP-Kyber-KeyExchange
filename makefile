.PHONY: build run

generate:
	go generate ./...

build: generate
	go build -o main

run: build
	sudo ./main -linkname xdptut-0fcd -ip-proto 2