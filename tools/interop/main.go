package main

import (
    "bytes"
    "compress/flate"
    "crypto/aes"
    "crypto/cipher"
    "crypto/ecdh"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "os"

    "github.com/klauspost/compress/s2"
)

// Run from references/gophertunnel to use its pinned compression dependency.
// All keys below are public, deterministic test fixtures, never production secrets.
func main() {
    plain := bytes.Repeat([]byte("Bedrock Snappy interoperability. "), 100)
    compressed := s2.EncodeSnappy(nil, plain)
    var flateBuffer bytes.Buffer
    writer, _ := flate.NewWriter(&flateBuffer, 6)
    writer.Write(plain)
    writer.Close()
    key := bytes.Repeat([]byte{0x42}, 32)
    block, _ := aes.NewCipher(key)
    iv := append(append([]byte{}, key[:12]...), 0, 0, 0, 2)
    stream := cipher.NewCTR(block, iv)
    var encrypted [][]byte
    for i, p := range [][]byte{[]byte("abc"), []byte("12345678901234567"), []byte("hi")} {
        var count [8]byte
        binary.LittleEndian.PutUint64(count[:], uint64(i))
        h := sha256.New()
        h.Write(count[:]); h.Write(p); h.Write(key)
        out := append(append([]byte{}, p...), h.Sum(nil)[:8]...)
        stream.XORKeyStream(out, out)
        encrypted = append(encrypted, out)
    }
    scalarA, scalarB := make([]byte, 48), make([]byte, 48)
    scalarA[47], scalarB[47] = 1, 2
    a, _ := ecdh.P384().NewPrivateKey(scalarA)
    b, _ := ecdh.P384().NewPrivateKey(scalarB)
    shared, _ := a.ECDH(b.PublicKey())
    h := sha256.New()
    h.Write(bytes.Repeat([]byte{3}, 16)); h.Write(shared)
    result := map[string]any{
        "plain": hex.EncodeToString(plain),
        "snappy": hex.EncodeToString(compressed),
        "flate": hex.EncodeToString(flateBuffer.Bytes()),
        "ciphertext": []string{hex.EncodeToString(encrypted[0]), hex.EncodeToString(encrypted[1]), hex.EncodeToString(encrypted[2])},
        "ecdh_key": hex.EncodeToString(h.Sum(nil)),
    }
    if len(os.Args) == 2 {
        zigEncoded, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
        decoded, err := s2.Decode(nil, zigEncoded); if err != nil { panic(err) }
        if !bytes.Equal(decoded, plain) { panic("Zig Snappy interoperability mismatch") }
    }
    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}
