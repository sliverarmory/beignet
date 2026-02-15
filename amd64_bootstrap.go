package beignet

import (
	"encoding/binary"
	"fmt"
)

const amd64BootstrapLen = 59

// buildAMD64Bootstrap returns a small x86_64 stub which:
// - sets rdi = base + payloadOffset
// - sets rsi = payloadSize
// - sets rdx = base + symbolOffset
// - calls base + loaderEntryOffsetAbs (then returns to the caller)
func buildAMD64Bootstrap(payloadOffset, payloadSize, symbolOffset, loaderEntryOffsetAbs uint64) ([]byte, error) {
	b := make([]byte, 0, amd64BootstrapLen)

	// lea r9, [rip-7] ; recover the shellcode base (start of this instruction)
	b = append(b, 0x4c, 0x8d, 0x0d, 0xf9, 0xff, 0xff, 0xff)

	// rdi = base + payloadOffset
	b = append(b, 0x48, 0xbf)
	b = appendU64LE(b, payloadOffset)
	b = append(b, 0x4c, 0x01, 0xcf) // add rdi, r9

	// rsi = payloadSize
	b = append(b, 0x48, 0xbe)
	b = appendU64LE(b, payloadSize)

	// rdx = base + symbolOffset
	b = append(b, 0x48, 0xba)
	b = appendU64LE(b, symbolOffset)
	b = append(b, 0x4c, 0x01, 0xca) // add rdx, r9

	// rax = base + loaderEntryOffsetAbs
	b = append(b, 0x48, 0xb8)
	b = appendU64LE(b, loaderEntryOffsetAbs)
	b = append(b, 0x4c, 0x01, 0xc8) // add rax, r9
	b = append(b, 0xff, 0xd0)       // call rax (keeps stack alignment for System V ABI)
	b = append(b, 0xc3)             // ret

	if len(b) != amd64BootstrapLen {
		return nil, fmt.Errorf("beignet: unexpected bootstrap length: got=%d want=%d", len(b), amd64BootstrapLen)
	}
	return b, nil
}

func appendU64LE(out []byte, v uint64) []byte {
	var imm [8]byte
	binary.LittleEndian.PutUint64(imm[:], v)
	return append(out, imm[:]...)
}
