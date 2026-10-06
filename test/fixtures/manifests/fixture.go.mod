module example.com/scanmanifest/fixture

go 1.24.7

require example.com/localmod v0.0.0

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
	golang.org/x/net v0.7.0 // indirect
)

replace example.com/localmod => ./localmod

exclude golang.org/x/crypto v0.0.0-20210921155107-089bfa567519

replace github.com/pkg/errors => github.com/go-errors/errors v1.4.2
