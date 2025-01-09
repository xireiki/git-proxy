all:
	go build -v -trimpath -ldflags "-s -w"
