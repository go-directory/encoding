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
		WritePrimitiveLength(out[2:2+n], l)
		copy(out[2+n:], v)
	}

	return out, nil
}

/*
WritePrimitiveTLV returns an instance of []byte
*/
func WritePrimitiveTLV(dst []byte, class byte, tag uint32, payload []byte) []byte {
	// primitive tag byte
	first := (class << 6) | byte(tag)

	// encode length
	l := len(payload)
	if l < 128 {
		dst = append(dst, first, byte(l))
	} else {
		n := LengthBytes(l)
		dst = append(dst, first, 0x80|byte(n))
		var tmp [4]byte
		WritePrimitiveLength(tmp[len(tmp)-n:], l)
		dst = append(dst, tmp[len(tmp)-n:]...)
	}

	// payload
	return append(dst, payload...)
}

func ReadExpectedPrimitiveTLV(buf []byte, p *int, class byte, tag uint32) ([]byte, error) {
	if *p >= len(buf) {
		return nil, errEOF
	}

	// read tag byte
	tagByte := buf[*p]
	*p++

	rcvrClass := tagByte >> 6
	rcvrCons := (tagByte & 0x20) != 0
	rcvrTag := uint32(tagByte & 0x1F)

	// primitive must have constructed = false
	if rcvrClass != class || rcvrCons != false || rcvrTag != tag {
		return nil, asn1Error("primitive tag mismatch")
	}

	// read primitive length
	if *p >= len(buf) {
		return nil, errEOF
	}

	l, n := ReadPrimitiveLength(buf[*p:])
	if n == 0 {
		return nil, errLength
	}
	*p += n

	if *p+l > len(buf) {
		return nil, errEOF
	}

	out := buf[*p : *p+l]
	*p += l

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
WritePrimitiveLength writes length l to dst.
*/
func WritePrimitiveLength(dst []byte, l int) {
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

func ReadPrimitiveLength(b []byte) (int, int) {
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
