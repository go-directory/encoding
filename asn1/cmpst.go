package asn1

/*
TLV implements a complete Type-Length-Value construct, useful for
building PKI or document structures.
*/
type TLV struct {
	Tag         byte
	Class       byte
	Constructed bool
	Length      int
	Value       []byte
	Children    []TLV
}

/*
Tag implements a container for a class byte, a constructed bool
and an ASN.1 tag uint32 when extracted from a payload.
*/
type Tag struct {
	Class       byte
	Constructed bool
	Tag         uint32
}

/*
WriteConstructedTag returns an instance of []byte containing the input
class, constructed and tagNumber values.

This method supports the high-tag-number form.
*/
func WriteConstructedTag(dst []byte, class byte, constructed bool, tagNum uint32) []byte {
	var first byte
	first = (class << 6)
	if constructed {
		first |= 0x20
	}

	if tagNum < 31 {
		first |= byte(tagNum)
		return append(dst, first)
	}

	// high-tag-number form
	first |= 0x1F
	dst = append(dst, first)

	// encode tagNum in base-128 big-endian with MSB continuation
	var buf [6]byte
	i := len(buf)
	n := tagNum
	for {
		i--
		buf[i] = byte(n & 0x7F)
		n >>= 7
		if n == 0 {
			break
		}
	}

	// set continuation bits except last
	for j := i; j < len(buf)-1; j++ {
		buf[j] |= 0x80
	}

	return append(dst, buf[i:]...)
}

func WriteConstructedLength(dst []byte, n int) []byte {
	if n < 0 {
		panic("negative length")
	}

	if n <= 127 {
		return append(dst, byte(n))
	}

	// long form
	var tmp [8]byte
	l := 0
	v := uint64(n)
	for v > 0 {
		tmp[l] = byte(v & 0xFF)
		v >>= 8
		l++
	}

	dst = append(dst, 0x80|byte(l))

	for i := l - 1; i >= 0; i-- {
		dst = append(dst, tmp[i])
	}

	return dst
}

func WriteConstructedTLV(dst []byte, class byte, constructed bool, tagNum uint32, payload []byte) []byte {
	dst = WriteConstructedTag(dst, class, constructed, tagNum)
	dst = WriteConstructedLength(dst, len(payload))
	return append(dst, payload...)
}

func ReadConstructedTag(buf []byte, p *int) (Tag, error) {
	if *p >= len(buf) {
		return Tag{}, errEOF
	}

	bt := buf[*p]
	*p++

	class := bt >> 6
	constructed := (bt & 0x20) != 0
	tagNum := uint32(bt & 0x1F)

	if tagNum == 0x1F {
		var n uint32
		for {
			if *p >= len(buf) {
				return Tag{}, errEOF
			}
			b := buf[*p]
			*p++

			n = (n << 7) | uint32(b&0x7F)
			if b&0x80 == 0 {
				break
			}
		}
		tagNum = n
	}

	return Tag{Class: class, Constructed: constructed, Tag: tagNum}, nil
}

func ReadConstructedLength(buf []byte, p *int) (int, error) {
	if *p >= len(buf) {
		return 0, errEOF
	}

	first := buf[*p]
	*p++

	if first&0x80 == 0 {
		return int(first), nil
	}

	n := int(first & 0x7F)
	if n == 0 || n > 8 {
		return 0, errLength
	}

	if *p+n > len(buf) {
		return 0, errEOF
	}

	val := 0
	for i := 0; i < n; i++ {
		val = (val << 8) | int(buf[*p+i])
	}

	*p += n
	return val, nil
}

func ReadConstructedTLV(buf []byte, p *int) (head Tag, out []byte, err error) {
	head, err = ReadConstructedTag(buf, p)
	if err != nil {
		return
	}

	var l int
	l, err = ReadConstructedLength(buf, p)
	if err != nil {
		return
	}

	if l == 0 {
		return
	}

	if *p+l > len(buf) {
		err = errEOF
		return
	}

	out = buf[*p : *p+l]
	*p += l

	return
}
