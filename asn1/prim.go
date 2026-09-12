package asn1

/*
EncodePrimitive returns an instance of []byte alongside an
error following an attempt to encode v based on tag t.
*/
func EncodePrimitive(t byte, v []byte) ([]byte, error) {
	l := len(v)
	var out []byte

	switch {
	case l < 128:
		out = make([]byte, 2+l)
		out[0] = t
		out[1] = byte(l)
		copy(out[2:], v)
	default:
		n := LengthBytes(l)
		out = make([]byte, 1+1+n+l)
		out[0] = t
		out[1] = 0x80 | byte(n)
		WriteLength(out[2:2+n], l)
		copy(out[2+n:], v)
	}

	return out, nil
}

/*
LengthBytes returns the number of bytes required to hold l.
*/
func LengthBytes(l int) int {
	switch {
	case l < 256:
		return 1
	case l < 65536:
		return 2
	case l < 16777216:
		return 3
	default:
		return 4
	}
}

/*
WriteLength writes length l to dst.
*/
func WriteLength(dst []byte, l int) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(l)
		l >>= 8
	}
}

func encodeLength(l int) []byte {
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
