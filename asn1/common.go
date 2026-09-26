package asn1

import (
	"strconv"
)

var (
	itoa = strconv.Itoa
)

/*
WriteLength appends ASN.1 BER/DER length encoding to dst.
*/
func WriteLength(dst []byte, l int) []byte {
	if l < 0 {
		panic("negative length")
	}

	if l < 128 {
		return append(dst, byte(l))
	}

	n := LengthBytes(l)

	dst = append(dst, 0x80|byte(n))

	var tmp [8]byte

	for i := n - 1; i >= 0; i-- {
		tmp[i] = byte(l)
		l >>= 8
	}

	return append(dst, tmp[:n]...)
}

/*
ReadLength returns two integer values, the first for the length and
the second for the number of bytes required to store the first.

When feeding this function a complete payload -- that is, an encoded
value that has not yet been broken down into its base TLV components --
one must truncate the first byte (the class/tag byte) via something
like:

	ln, lb := ReadLength(yourPayload[1:])
	...
*/
func ReadLength(b []byte) (int, int) {
	if len(b) == 0 {
		return 0, 0
	}
	if b[0] < 128 {
		return int(b[0]), 1
	}
	n := int(b[0] & 0x7F)
	if len(b) < 1+n {
		return 0, 0
	}
	l := 0
	for i := 0; i < n; i++ {
		l = (l << 8) | int(b[1+i])
	}
	return l, 1 + n
}
