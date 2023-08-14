module github.com/projectcollection/chirpy

go 1.21.0

replace github.com/projectcollection/chirpy/internals/storage v0.0.0 => ./internals/storage/

require (
	github.com/go-chi/chi/v5 v5.0.10
	github.com/projectcollection/chirpy/internals/storage v0.0.0
)

require golang.org/x/crypto v0.12.0 // indirect
