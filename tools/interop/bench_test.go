package main

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/s2"
)

const corpusDirectory = "../../zig-out/bench-corpus"
const outputLimit = (1 << 20) - 10

func read(t testing.TB, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func corpus(t testing.TB) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(corpusDirectory, "*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 9 {
		t.Fatalf("expected nine generated batches, got %d; run bedwire-codecs first", len(paths))
	}
	micro, err := filepath.Glob(filepath.Join(corpusDirectory, "micro", "*.raw"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, micro...)
	return paths
}

func TestSnappyInteroperability(t *testing.T) {
	var fixture struct{ Plain, Snappy string }
	if err := json.Unmarshal(read(t, "../../tests/compression/interop.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	plain, err := hex.DecodeString(fixture.Plain)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := hex.DecodeString(fixture.Snappy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := s2.Decode(nil, encoded)
	if err != nil || !bytes.Equal(plain, decoded) {
		t.Fatalf("existing fixture mismatch: %v", err)
	}
	for _, path := range corpus(t) {
		plain := read(t, path)
		base := strings.TrimSuffix(path, ".raw")
		zig := read(t, base+".snappy")
		decoded, err := s2.Decode(make([]byte, len(plain)), zig)
		if err != nil || !bytes.Equal(plain, decoded) {
			t.Fatalf("Zig Snappy mismatch: %s: %v", path, err)
		}
		if filepath.Base(filepath.Dir(path)) != "micro" {
			for _, source := range []string{"flate", "libflate"} {
				reader := flate.NewReader(bytes.NewReader(read(t, base+"."+source)))
				decoded, err = io.ReadAll(io.LimitReader(reader, int64(len(plain)+1)))
				reader.Close()
				if err != nil || !bytes.Equal(plain, decoded) {
					t.Fatalf("DEFLATE mismatch: %s: %v", path, err)
				}
			}
		}
		reference := s2.EncodeSnappy(make([]byte, outputLimit), plain)
		if len(reference) > outputLimit {
			t.Fatal("reference exceeds output limit")
		}
		if err := os.WriteFile(base+".s2snappy", reference, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkSnappy(b *testing.B) {
	for _, path := range corpus(b) {
		plain := read(b, path)
		base := strings.TrimSuffix(path, ".raw")
		name := filepath.Base(base)
		b.Run(name+"/encode", func(b *testing.B) {
			output := make([]byte, outputLimit)
			for range 32 {
				s2.EncodeSnappy(output, plain)
			}
			b.SetBytes(int64(len(plain)))
			b.ReportAllocs()
			for b.Loop() {
				encoded := s2.EncodeSnappy(output, plain)
				if len(encoded) > outputLimit {
					b.Fatal("reference exceeds output limit")
				}
			}
		})
		for _, source := range []string{"snappy", "s2snappy"} {
			encoded := read(b, base+"."+source)
			b.Run(name+"/decode/"+source, func(b *testing.B) {
				output := make([]byte, 4<<20)
				for range 32 {
					if _, err := s2.Decode(output, encoded); err != nil {
						b.Fatal(err)
					}
				}
				b.SetBytes(int64(len(plain)))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := s2.Decode(output, encoded); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
