LDFLAGS = -X cypherpunks.ru/gogost.Version=$(VERSION)

all: streebog256 streebog512

streebog256:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/gogost/cmd/streebog256

streebog512:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/gogost/cmd/streebog512

bench:
	GOPATH=$(GOPATH) go test -benchmem -bench . cypherpunks.ru/gogost/...
