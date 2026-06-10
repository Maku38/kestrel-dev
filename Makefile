BINARY := kestrel

.PHONY: all build run clean

all: build

build:
	go generate ./...
	go build -o $(BINARY) .

run: build
	sudo ./$(BINARY)

clean:
	rm -f $(BINARY) bpf_*.go bpf_*.o