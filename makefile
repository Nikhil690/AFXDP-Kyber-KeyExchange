.PHONY: build run

generate:
	go generate ./...

build: generate
	go build -o main

run: build
	sudo ./main -linkname xdptut-0fcd -mode=request -dstip 10.11.1.2