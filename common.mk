LDFLAGS = -X cypherpunks.ru/gogost.Version=$(VERSION)

gogost-streebog:
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" cypherpunks.ru/gogost/gost34112012/cmd/gogost-streebog

bench:
	GOPATH=$(GOPATH) go test -benchmem -bench . cypherpunks.ru/gogost/...
