package gophernet

import (
	"crypto/ecdsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
)

const (
	MagicByte = 'g'
)

var (
	decoders map[int8]func([]byte) (interface{}, error)
)

type P256Sig struct {
	R [32]byte
	S [32]byte
}

func (p P256Sig) Get() (*big.Int, *big.Int) {
	r := make([]byte, 32)
	for i, v := range p.R {
		r[i] = v
	}
	r2 := big.NewInt(0)
	r2.SetBytes(r)

	s := make([]byte, 32)
	for i, v := range p.S {
		s[i] = v
	}
	s2 := big.NewInt(0)
	s2.SetBytes(s)
	return r2, s2
}

type Header struct {
	Magic   byte
	Version int8
	Hops    int8
	P256Sig
	Sender   [16]byte
	Encoding int8
	Length   int32
}

func (h *Header) Ping() bool {
	return h.Magic == MagicByte && h.Version == 0 && h.Hops == 0
}

func (h *Header) Valid() (errs []error) {
	if h.Magic != MagicByte {
		errs = append(errs, fmt.Errorf("Invalid magic byte: %q", h.Magic))
	}
	if h.Version != 1 {
		errs = append(errs, fmt.Errorf("Invalid version: %d", h.Version))
	}
	if _, ok := decoders[h.Encoding]; !ok {
		errs = append(errs, fmt.Errorf("Invalid encoding: %d", h.Encoding))
	}
	if h.Length < 1 {
		errs = append(errs, fmt.Errorf("Non-positive length: %d", h.Length))
	}
	return
}

type Message struct {
	RawHeader *Header
	RawBody   []byte
}

func PartialMessage(h *Header) *Message {
	return &Message{
		RawHeader: h,
		RawBody:   make([]byte, h.Length),
	}
}

// Verifies the message using SHA1 and the attached ECDSA signature.
func (m *Message) Verify(pubkey *ecdsa.PublicKey) bool {
	//FIXME Should probably do this without all the copying
	// 16 bytes for sender + 1 byte for encoding + 4 bytes for size + actual size
	signedPart := make([]byte, len(m.RawHeader.Sender)+1+4+int(m.RawHeader.Length))
	for i, v := range m.RawHeader.Sender {
		signedPart[i] = v
	}
	signedPart[16] = byte(m.RawHeader.Encoding)
	binary.BigEndian.PutUint32(signedPart[17:], uint32(m.RawHeader.Length))
	copy(signedPart[21:], m.RawBody)

	rawHash := sha1.Sum(signedPart)
	hash := make([]byte, 20)
	for i := 0; i < len(rawHash); i++ {
		hash[i] = rawHash[i]
	}
	r, s := m.RawHeader.P256Sig.Get()
	return ecdsa.Verify(pubkey, hash, r, s)
}
