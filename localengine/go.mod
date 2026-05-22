module github.com/salman/clever-relay/localengine

go 1.26.2

require (
	github.com/salman/clever-relay/dataengine v0.0.0
	golang.org/x/net v0.54.0
)

require (
	github.com/klauspost/compress v1.18.6 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)

replace github.com/salman/clever-relay/dataengine => ../dataengine
