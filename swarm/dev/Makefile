.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    github.com/Anson5Lee/anson_bc/cmd/swarm
	go build -o bin/geth     github.com/Anson5Lee/anson_bc/cmd/geth
	go build -o bin/bootnode github.com/Anson5Lee/anson_bc/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v github.com/Anson5Lee/anson_bc/swarm/...
