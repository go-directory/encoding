package asn1

/*
integer.go implements the codec for the UNBOUNDED ASN.1
INTEGER type using generics.  This functionality lends
itself to X.680 number forms (OID arcs) when used in an
unsigned context.
*/

import (
	"math/big"
)

/*
INTEGER encompasses int, int64, uint, uint64 and *big.Int
types to implement an UNBOUNDED ASN.1 INTEGER.
*/
type INTEGER interface {
	~int | ~uint | ~int64 | ~uint64 | *big.Int
}

/*
EncodeInteger returns the full TLV form of the input value.
*/
func EncodeInteger[T INTEGER](v T) []byte {
	var val []byte

	switch tv := any(v).(type) {
	case uint64:
		val = encodeUint64(tv)
	case uint:
		val = encodeUint64(uint64(tv))
	case int64:
		val = encodeInt64(tv)
	case int:
		val = encodeInt64(int64(tv))
	case *big.Int:
		val = encodeBigInt(tv)
	default:
		return nil
	}

	out := []byte{TagInteger}
	out = append(out, encodeIntegerLength(len(val))...)
	out = append(out, val...)
	return out
}

/*
DecodeInteger returns the requested numeric type T (int64, uint64, *big.Int)
alongside an error following an attempt to decode enc.
*/
func DecodeInteger[T INTEGER](enc []byte) (T, error) {
	var zero T

	if len(enc) < 2 || enc[0] != TagInteger {
		return zero, asn1Error("INTEGER: decode failed: invalid tag or length")
	}

	l, n := ReadLength(enc[1:])
	if n == 0 || len(enc) < 1+n+l {
		return zero, asn1Error("INTEGER: decode failed: failed to read primitive length octet(s)")
	}

	v := enc[1+n : 1+n+l]

	switch any(zero).(type) {
	case int64, int:
		return decodeSigned[T](v)

	case uint64, uint:
		return decodeUnsigned[T](v)

	case *big.Int:
		return any(decodeBigInt(v)).(T), nil
	}

	return zero, asn1Error("INTEGER: decode failed: unsupported input type")
}

func decodeSigned[T INTEGER](v []byte) (out T, err error) {
	var zero T
	if len(v) > 8 {
		err = asn1Error("INTEGER: too large for signed integer")
		return
	}

	s := decodeInt64(v)
	switch any(zero).(type) {
	case int64:
		out = any(int64(s)).(T)

	case int:
		out = any(int(s)).(T)
	}

	return out, err
}

func decodeUnsigned[T INTEGER](v []byte) (out T, err error) {
	var zero T
	if len(v) > 8 {
		err = asn1Error("INTEGER: too large for unsigned integer")
		return
	}

	s := decodeInt64(v)
	if s < 0 {
		err = asn1Error("INTEGER: negative value not allowed for unsigned integer")
		return
	}

	switch any(zero).(type) {
	case uint64:
		out = any(uint64(s)).(T)

	case uint:
		out = any(uint(s)).(T)
	}

	return out, err
}

func encodeInt64(n int64) []byte {
	if n == 0 {
		return []byte{0x00}
	}

	var tmp [8]byte
	v := uint64(n)
	i := len(tmp)

	for v != 0 && i > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}

	out := tmp[i:]

	// Positive: ensure MSB = 0
	if n > 0 && out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}

	// Negative: ensure MSB = 1
	if n < 0 && out[0]&0x80 == 0 {
		out = append([]byte{0xFF}, out...)
	}

	return out
}

func encodeUint64(u uint64) []byte {
	if u == 0 {
		return []byte{0x00}
	}

	var tmp [8]byte
	i := len(tmp)

	for u != 0 && i > 0 {
		i--
		tmp[i] = byte(u)
		u >>= 8
	}

	out := tmp[i:]

	// Ensure MSB = 0 (positive)
	if out[0]&0x80 != 0 {
		out = append([]byte{0x00}, out...)
	}

	return out
}

func decodeInt64(b []byte) int64 {
	var n int64
	for i := 0; i < len(b); i++ {
		n = (n << 8) | int64(b[i])
	}
	shift := 64 - uint(len(b))*8
	n = (n << shift) >> shift
	return n
}

func encodeBigInt(b *big.Int) []byte {
	if b.Sign() == 0 {
		return []byte{0x00}
	}

	if b.Sign() > 0 {
		v := b.Bytes()
		if v[0]&0x80 != 0 {
			v = append([]byte{0x00}, v...)
		}
		return v
	}

	// negative: two's complement
	mag := new(big.Int).Abs(b).Bytes()
	if len(mag) == 0 {
		return []byte{0xFF}
	}

	buf := make([]byte, len(mag))
	for i := range mag {
		buf[i] = ^mag[i]
	}

	// add 1
	carry := byte(1)
	for i := len(buf) - 1; i >= 0 && carry != 0; i-- {
		sum := uint16(buf[i]) + uint16(carry)
		buf[i] = byte(sum)
		carry = byte(sum >> 8)
	}

	if buf[0]&0x80 == 0 {
		buf = append([]byte{0xFF}, buf...)
	}

	return buf
}

func decodeBigInt(b []byte) *big.Int {
	if len(b) == 0 {
		return new(big.Int)
	}

	// positive
	if b[0]&0x80 == 0 {
		return new(big.Int).SetBytes(b)
	}

	// negative: two's complement
	tmp := make([]byte, len(b))
	for i := range b {
		tmp[i] = ^b[i]
	}

	// add 1
	carry := byte(1)
	for i := len(tmp) - 1; i >= 0 && carry != 0; i-- {
		sum := uint16(tmp[i]) + uint16(carry)
		tmp[i] = byte(sum)
		carry = byte(sum >> 8)
	}

	mag := new(big.Int).SetBytes(tmp)
	return mag.Neg(mag)
}

func encodeIntegerLength(l int) []byte {
	if l < 128 {
		return []byte{byte(l)}
	}
	// long form
	var tmp [4]byte
	i := len(tmp)
	v := l
	for v != 0 && i > 0 {
		i--
		tmp[i] = byte(v)
		v >>= 8
	}
	out := tmp[i:]
	return append([]byte{0x80 | byte(len(out))}, out...)
}
