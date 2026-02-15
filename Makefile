 BIN_OUTPUT := dist/lvs
 
 
 .DEFAULT_GOAL := build
 fmt:
	go fmt ./...
 
 lint: fmt
	golint ./...
 .PHONY:lint
 vet: fmt
	go vet ./...
 .PHONY:vet
 build: vet
	go build -o ${BIN_OUTPUT} .
 .PHONY:build

docker: vet
	docker build . -t lego-vault-sync
