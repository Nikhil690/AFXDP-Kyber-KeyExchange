.PHONY: build run env xdpiface tear-env

generate:
	go generate ./...

build: generate
	go build -o main

run: build
	sudo ./main -linkname afxdp

env:
	eval $(env/testenv.sh alias)

xdpiface:
	t setup --name afxdp

tear-env: 
	t teardown