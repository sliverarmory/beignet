package beignet

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestBuildAMD64Bootstrap_Layout(t *testing.T) {
	cases := [][4]uint64{
		{0, 0, 0, 0},
		{1, 2, 3, 4},
		{0xffff, 0x10000, 0x12345678, 0xdeadbeef},
		{0x1122334455667788, 0x8877665544332211, 0x0, 0xffffffffffffffff},
		{0x1000, 0x2000, 0x3000, 0x4000},
	}

	r := rand.New(rand.NewSource(7331))
	for i := 0; i < 32; i++ {
		cases = append(cases, [4]uint64{r.Uint64(), r.Uint64(), r.Uint64(), r.Uint64()})
	}

	for i, tc := range cases {
		got, err := buildAMD64Bootstrap(tc[0], tc[1], tc[2], tc[3])
		if err != nil {
			t.Fatalf("case %d: buildAMD64Bootstrap error: %v", i, err)
		}
		if len(got) != amd64BootstrapLen {
			t.Fatalf("case %d: bootstrap length got=%d want=%d", i, len(got), amd64BootstrapLen)
		}

		// lea r9, [rip-7]
		if !bytes.Equal(got[0:7], []byte{0x4c, 0x8d, 0x0d, 0xf9, 0xff, 0xff, 0xff}) {
			t.Fatalf("case %d: unexpected lea prefix: % x", i, got[0:7])
		}

		if !bytes.Equal(got[7:9], []byte{0x48, 0xbf}) {
			t.Fatalf("case %d: unexpected movabs rdi opcode", i)
		}
		if payload := binary.LittleEndian.Uint64(got[9:17]); payload != tc[0] {
			t.Fatalf("case %d: payload imm got=0x%x want=0x%x", i, payload, tc[0])
		}
		if !bytes.Equal(got[17:20], []byte{0x4c, 0x01, 0xcf}) {
			t.Fatalf("case %d: unexpected add rdi,r9 opcode", i)
		}

		if !bytes.Equal(got[20:22], []byte{0x48, 0xbe}) {
			t.Fatalf("case %d: unexpected movabs rsi opcode", i)
		}
		if payloadSize := binary.LittleEndian.Uint64(got[22:30]); payloadSize != tc[1] {
			t.Fatalf("case %d: payload size imm got=0x%x want=0x%x", i, payloadSize, tc[1])
		}

		if !bytes.Equal(got[30:32], []byte{0x48, 0xba}) {
			t.Fatalf("case %d: unexpected movabs rdx opcode", i)
		}
		if symbol := binary.LittleEndian.Uint64(got[32:40]); symbol != tc[2] {
			t.Fatalf("case %d: symbol imm got=0x%x want=0x%x", i, symbol, tc[2])
		}
		if !bytes.Equal(got[40:43], []byte{0x4c, 0x01, 0xca}) {
			t.Fatalf("case %d: unexpected add rdx,r9 opcode", i)
		}

		if !bytes.Equal(got[43:45], []byte{0x48, 0xb8}) {
			t.Fatalf("case %d: unexpected movabs rax opcode", i)
		}
		if loader := binary.LittleEndian.Uint64(got[45:53]); loader != tc[3] {
			t.Fatalf("case %d: loader imm got=0x%x want=0x%x", i, loader, tc[3])
		}
		if !bytes.Equal(got[53:56], []byte{0x4c, 0x01, 0xc8}) {
			t.Fatalf("case %d: unexpected add rax,r9 opcode", i)
		}
		if !bytes.Equal(got[56:60], []byte{0x48, 0x83, 0xec, 0x08}) {
			t.Fatalf("case %d: unexpected sub rsp,8 opcode", i)
		}
		if !bytes.Equal(got[60:62], []byte{0xff, 0xd0}) {
			t.Fatalf("case %d: unexpected call rax opcode", i)
		}
		if !bytes.Equal(got[62:66], []byte{0x48, 0x83, 0xc4, 0x08}) {
			t.Fatalf("case %d: unexpected add rsp,8 opcode", i)
		}
		if got[66] != 0xc3 {
			t.Fatalf("case %d: unexpected ret opcode", i)
		}
	}
}
