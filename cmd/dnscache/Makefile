all:
	GOGC="off" go test -bench . 

check: 
	gofmt -w -s .
	CGO_ENABLED=0 staticcheck
