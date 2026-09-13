package vlq

/*
vlq.go pertains to the encoding and decoding of numerical
types, such as uint64, int64 and *big.Int. These, in turn,
are used for instances of ASN.1 INTEGER in varying forms.
*/

import (
	"errors"
	"math/big"
)

/*
INTEGER encompasses int64, uint64 and *big.Int types to
implement an UNBOUNDED ASN.1 INTEGER.
*/
type INTEGER interface {
        ~int64 | ~uint64 | *big.Int
}

/*
Encode returns the variable length quantity encoding
of the input value.
*/
func Encode[T INTEGER](v T) []byte {
	var enc []byte

	switch tv := any(v).(type) {
	case uint64:
		enc = vlqEncodeUint64(tv)
	case int64:
		enc = vlqEncodeInt64(tv)
	case *big.Int:
		enc = vlqEncodeBig(zigzagEncodeBig(tv))
	}

	return enc
}

/*
Decode decodes enc into the return instance, which will
be uint64, int64 or *[big.Int].
*/
func Decode[T INTEGER](enc []byte, p *int) (any, error) {
	var (
		zero T
		dec  any
		err  error
		//done bool
	)

	switch any(zero).(type) {
	case int64:
		dec, _, err = vlqDecodeInt64(enc, p)
	case uint64:
		dec, _, err = vlqDecodeUint64(enc, p)
	case *big.Int:
		var u *big.Int
		if u, err = vlqDecodeBig(enc, p); err == nil {
			dec = zigzagDecodeBig(u)
		}
	}

	return dec, err
}

func vlqEncodeUint64(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}

	var buf [16]byte
	i := len(buf)

	for n > 0 {
		i--
		b := byte(n & 0x7F) // take 7 bits
		n >>= 7

		if len(buf)-i > 1 { // set continuation bit except on last octet
			b |= 0x80
		}
		buf[i] = b
	}

	return buf[i:]
}

func vlqEncodeBig(n *big.Int) []byte {
	if n.Sign() == 0 {
		return []byte{0}
	}

	tmp := new(big.Int).Set(n)
	rem := new(big.Int).SetUint64(0)

	out := make([]byte, 0, 16)

	for tmp.Sign() != 0 {
		tmp.DivMod(tmp, new(big.Int).SetUint64(128), rem)
		b := byte(rem.Uint64())
		out = append(out, b)
	}

	// reverse and set continuation bits
	for i := 0; i < len(out)/2; i++ {
		out[i], out[len(out)-1-i] = out[len(out)-1-i], out[i]
	}

	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}

	return out
}

func vlqDecodeUint64(buf []byte, p *int) (uint64, bool, error) {
	var u uint64

	for {
		if *p >= len(buf) {
			return 0, false, errBadVLQ
		}

		b := buf[*p]
		seven := uint64(b & 0x7F)

		// Would shifting overflow?
		if u > (^(uint64(0)) >> 7) {
			// Do NOT consume this byte; let big path handle it.
			return u, false, nil
		}

		// Safe to consume
		*p++
		u = (u << 7) | seven

		if b&0x80 == 0 {
			return u, true, nil
		}
	}
}

func vlqDecodeBig(buf []byte, p *int) (*big.Int, error) {
	n := new(big.Int).SetUint64(0) //.SetUint64(prefix)

	for {
		if *p >= len(buf) {
			return n, errBadVLQ
		}

		b := buf[*p]
		*p++

		seven := int64(b & 0x7F)

		n.Lsh(n, 7)
		n.Or(n, new(big.Int).SetInt64(seven))

		if b&0x80 == 0 {
			return n, nil
		}
	}
}

// "zigzagging" maps signed int64 to unsigned uint64 for VLQ.
func zigzagEncodeInt64(n int64) uint64 {
	return uint64(uint64(n<<1) ^ uint64(n>>63))
}

func zigzagDecodeInt64(u uint64) int64 {
	return int64((u >> 1) ^ uint64(-(u & 1)))
}

func vlqDecodeInt64(buf []byte, p *int) (int64, bool, error) {
	var u uint64

	for {
		if *p >= len(buf) {
			return 0, false, errBadVLQ
		}

		b := buf[*p]
		seven := uint64(b & 0x7F)

		// Would shifting overflow?
		if u > (^(uint64(0)) >> 7) {
			// Do NOT consume this byte; let caller decide what to do.
			return int64(zigzagDecodeInt64(u)), false, nil
		}

		// Safe to consume
		*p++
		u = (u << 7) | seven

		if b&0x80 == 0 {
			return zigzagDecodeInt64(u), true, nil
		}
	}
}

func vlqEncodeInt64(n int64) []byte {
	u := zigzagEncodeInt64(n)
	if u == 0 {
		return []byte{0}
	}

	var buf [16]byte
	i := len(buf)

	for u > 0 {
		i--
		b := byte(u & 0x7F) // take 7 bits
		u >>= 7

		if len(buf)-i > 1 { // set continuation bit except on last octet
			b |= 0x80
		}
		buf[i] = b
	}

	return buf[i:]
}

var (
	errBadVLQ = errors.New("INTEGER: bad VLQ")
)

// Signed big.Int to unsigned big.Int
func zigzagEncodeBig(n *big.Int) *big.Int {
	if n.Sign() >= 0 {
		return new(big.Int).Lsh(n, 1)
	}
	tmp := new(big.Int).Neg(n)  // -n
	tmp.Lsh(tmp, 1)             // << 1
	tmp.Sub(tmp, big.NewInt(1)) // -1
	return tmp
}

// Unsigned big.Int to signed big.Int
func zigzagDecodeBig(u *big.Int) *big.Int {
	s := new(big.Int).And(u, big.NewInt(1)) // low bit
	v := new(big.Int).Rsh(u, 1)

	if s.Sign() == 0 {
		return v
	}

	v.Add(v, big.NewInt(1))
	return v.Neg(v)
}
