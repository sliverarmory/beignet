# Beignet

Converts .dylib files to MacOS shellcode, use as a CLI or import as a golang library.

### CLI

Convert a dylib to a raw shellcode buffer:

`./beignet --out payload.bin ./payload.dylib`

### Comple from Source

`make`

### Regenerating the embedded loader (darwin/arm64)

`go generate ./internal/stager`
