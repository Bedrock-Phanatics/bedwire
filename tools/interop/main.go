package main

import (
    "bufio"
    "bytes"
    "io"
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
    if len(os.Args) >= 2 {
        zigEncoded, err := os.ReadFile(os.Args[1]); if err != nil { panic(err) }
        decoded, err := s2.Decode(nil, zigEncoded); if err != nil { panic(err) }
        if !bytes.Equal(decoded, plain) { panic("Zig Snappy interoperability mismatch") }
    }
    if len(os.Args) == 3 {
        checkFrames(os.Args[2], key)
    }
    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil { panic(err) }
}

func checkFrames(path string, key []byte) {
    data, err := os.ReadFile(path); if err != nil { panic(err) }
    reader := bytes.NewReader(data)
    block := func() []byte {
        var size uint32
        if err := binary.Read(reader, binary.LittleEndian, &size); err != nil { panic(err) }
        out := make([]byte, size)
        if _, err := io.ReadFull(reader, out); err != nil { panic(err) }
        return out
    }
    type stream struct { algorithm byte; frames [][]byte }
    var streams []stream
    for i := 0; i < 2; i++ {
        algorithm, err := reader.ReadByte(); if err != nil { panic(err) }
        var count uint32
        if err := binary.Read(reader, binary.LittleEndian, &count); err != nil { panic(err) }
        s := stream{algorithm: algorithm}
        for j := uint32(0); j < count; j++ { s.frames = append(s.frames, block()) }
        streams = append(streams, s)
    }
    var count uint32
    if err := binary.Read(reader, binary.LittleEndian, &count); err != nil { panic(err) }
    var expected [][]byte
    for i := uint32(0); i < count; i++ { expected = append(expected, block()) }

    for _, s := range streams {
        if len(s.frames) < 2 { panic("expected the group to split") }
        cipherBlock, _ := aes.NewCipher(key)
        ctr := cipher.NewCTR(cipherBlock, append(append([]byte{}, key[:12]...), 0, 0, 0, 2))
        var got [][]byte
        sawUncompressed := false
        for counter, frame := range s.frames {
            if frame[0] != 0xfe { panic("missing batch header") }
            body := append([]byte{}, frame[1:]...)
            ctr.XORKeyStream(body, body)
            payload, mac := body[:len(body)-8], body[len(body)-8:]
            var number [8]byte
            binary.LittleEndian.PutUint64(number[:], uint64(counter))
            h := sha256.New(); h.Write(number[:]); h.Write(payload); h.Write(key)
            if !bytes.Equal(h.Sum(nil)[:8], mac) { panic("checksum mismatch") }
            var raw []byte
            switch payload[0] {
            case 0xff:
                raw = payload[1:]
                sawUncompressed = true
            case 0:
                if s.algorithm != 0 { panic("unexpected DEFLATE batch") }
                raw, err = io.ReadAll(flate.NewReader(bytes.NewReader(payload[1:]))); if err != nil { panic(err) }
            case 1:
                if s.algorithm != 1 { panic("unexpected Snappy batch") }
                raw, err = s2.Decode(nil, payload[1:]); if err != nil { panic(err) }
            default:
                panic("unknown compression marker")
            }
            packets := bufio.NewReader(bytes.NewReader(raw))
            for {
                size, err := binary.ReadUvarint(packets)
                if err == io.EOF { break }
                if err != nil { panic(err) }
                packet := make([]byte, size)
                if _, err := io.ReadFull(packets, packet); err != nil { panic(err) }
                got = append(got, packet)
            }
        }
        if !sawUncompressed { panic("expected an incompressible batch to go out uncompressed") }
        if len(got) != len(expected) { panic("packet count mismatch") }
        for i := range got {
            if !bytes.Equal(got[i], expected[i]) { panic("packet mismatch") }
        }
    }
}
