package asn1

/*
EncodePrimitive returns an instance of []byte alongside an
error following an attempt to encode v based on tag t into
a tag + length + value payload. [ClassUniversal] is assigned
implicitly.

The tag (t) is assumed to be the formal ASN.1 tag, for example
4 for OCTET STRING.

This method is meant to help in standalone encoding calls for
primitives. For encoding integer types, see [EncodeInteger].
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
WritePrimitiveTLV returns an instance of []byte following an attempt to encode
the input payload per class/tag bytes, returning the finished payload appended
to the input dst instance.

The class byte argument must be one of [ClassUniversal](0), [ClassApplication](1),
[ClassContextSpecific](2) or [ClassPrivate](3).

The tag uint32 argument represents either the official ASN.1 tag value, for example
4 for OCTET STRING, or a context tag "wrapper", e.g. "[7]", as defined within the
relevant ASN.1 module definition.

This method is meant to help in streamed encoding calls for primitives, or where
specialized wrapping is needed.
*/
func WritePrimitiveTLV(dst []byte, class byte, tag uint32, payload []byte) []byte {
	dst = WriteTag(dst, class, false, tag)
	dst = WriteLength(dst, len(payload))
	return append(dst, payload...)
}

/*
ReadExpectedPrimitiveTLV returns an instance of []byte alongside an error following
an attempt to process the tag, length and value bytes into discrete components.

The input buf argument represents the ASN.1-encoded payload.

The pointer to int argument represents the cursor position, which will increase in
magnitude as the base components encoded in buf are read.

The class byte argument must be one of [ClassUniversal](0), [ClassApplication](1),
[ClassContextSpecific](2) or [ClassPrivate](3).

The tag uint32 argument represents either the official ASN.1 tag value, for example
4 for OCTET STRING, or a context tag "wrapper", e.g. "[4]", as defined within the
relevant ASN.1 module definition.

The variadic noTruncate Boolean value controls whether the class, tag and length
bytes are actually truncated from the return value. By default, those bytes are
truncated, leaving only the base value.
*/
func ReadExpectedPrimitiveTLV(buf []byte, p *int, class byte, tag uint32, noTruncate ...bool) ([]byte, error) {
	if *p >= len(buf) {
		return nil, errEOF
	}

	start := *p // remember tag byte pos

	// read tag byte
	tagByte := buf[*p]
	*p++

	rcvrClass := tagByte >> 6
	rcvrCons := (tagByte & 0x20) != 0
	rcvrTag := uint32(tagByte & 0x1F)

	if rcvrClass != class || rcvrCons != false || rcvrTag != tag {
		return nil, asn1Error("primitive tag mismatch")
	}

	if *p >= len(buf) {
		return nil, errEOF
	}

	length, lengthBytes := ReadLength(buf[*p:])
	if lengthBytes == 0 {
		return nil, errLength
	}
	*p += lengthBytes

	if *p+length > len(buf) {
		return nil, errEOF
	}

	// payload-only slice
	payload := buf[*p : *p+length]

	// advance cursor past payload
	*p += length

	// if noTruncate[0] == true, return full TLV (tag + len + payload)
	if len(noTruncate) > 0 && noTruncate[0] {
		payload = buf[start:*p]
	}

	return payload, nil
}

/*
LengthBytes returns the number of bytes required to hold l.
This is a convenience function, and is mainly used for aid
in manual payload assembly.
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
