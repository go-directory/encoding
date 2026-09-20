package asn1

import (
	"strconv"
)

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
Expect returns an error if any of the input values do not correspond
to those present in the receiver instance.
*/
func (r TLV) Expect(class byte, constructed bool, tag uint32) error {
	return expect(r.Class, class, r.Constructed, constructed, uint32(r.Tag), tag)
}

/*
HasChildren returns a Boolean value indicative of the receiver
bearing one or more child [TLV] instances.
*/
func (r TLV) HasChildren() bool { return len(r.Children) > 0 }

/*
ReadExpectedConstructedTLV returns an instance of []byte alongside
an error following calls of [ReadConstructedTLV] and [Tag.Expect].

This is merely a convenience function.
*/
func ReadExpectedConstructedTLV(
	enc []byte,
	p *int,
	class byte,
	tag uint32,
) ([]byte, error) {

	t, payload, err := ReadConstructedTLV(enc, p)
	if err == nil {
		err = t.Expect(class, true, tag)
	}

	return payload, err
}

/*
UnwrapTLV returns an instance of []byte alongside an error following an
attempt to traverse the provided encoding according to the parameters
in the input variadic [Tag] instances.

Each [Tag] processes a single "layer" of the encoded structure. If
there are three [Tag] instances input, this function attempts to
traverse the same number of layers. The data encountered at the last
layer is the return payload.

This is merely a convenience function written to simply calls to the
[ReadExpectedConstructedTLV] function in iterative fashion.

See also [WrapTLV].
*/
func UnwrapTLV(enc []byte, tags ...Tag) ([]byte, error) {
	var err error
	if len(enc) == 0 {
		err = asn1Error("WalkTLV: empty input payload")
		return nil, err
	}

	cur := enc
	p := 0

	for i := 0; i < len(tags) && err == nil; i++ {
		want := tags[i]
		var payload []byte
		if want.Constructed {
			// constructed TLV
			if payload, err = ReadExpectedConstructedTLV(cur, &p, want.Class, want.Tag); err == nil {
				cur = payload
				p = 0
			}
		} else {
			if payload, err = ReadExpectedPrimitiveTLV(cur, &p, want.Class, want.Tag); err == nil {
				cur = payload
				p = 0
			}
		}
	}

	return cur, nil
}

/*
WrapTLV returns a []byte instance alongside an error following an
attempt to wrap the input buf value using the input [Tag] variadic
for structural guidance.

See also [UnwrapTLV].
*/
func WrapTLV(buf []byte, tags ...Tag) ([]byte, error) {
	if len(tags) == 0 {
		return nil, asn1Error("WrapTLV: no Tags found")
	}

	cur := buf
	for i := 0; i < len(tags); i++ {
		t := tags[i]

		if t.Constructed {
			cur = WriteConstructedTLV(
				nil,
				t.Class,
				true,
				t.Tag,
				cur,
			)
		} else {
			cur = WritePrimitiveTLV(
				nil,
				t.Class,
				t.Tag,
				cur,
			)
		}
	}

	return cur, nil
}

func expect(
	rcvrClass, assnClass byte,
	rcvrCons, assnCons bool,
	rcvrTag, assnTag uint32,
) (err error) {

	if err = expectClass(rcvrClass, assnClass); err == nil {
		if err = expectConstructed(rcvrCons, assnCons); err == nil {
			err = expectTag(rcvrTag, assnTag)
		}
	}

	return
}

func expectClass(rcvrClass, assnClass byte) (err error) {
	if rcvrClass != assnClass {
		err = asn1Error("asn1: wrong class: got ",
			strconv.Itoa(int(rcvrClass)), ", want ",
			strconv.Itoa(int(assnClass)))
	}
	return
}

func expectTag(rcvrTag, assnTag uint32) (err error) {
	if rcvrTag != assnTag {
		err = asn1Error("asn1: wrong tag: got ",
			strconv.Itoa(int(rcvrTag)), ", want ",
			strconv.Itoa(int(assnTag)))
	}
	return
}

func expectConstructed(rcvrCons, assnCons bool) (err error) {
	if rcvrCons != assnCons {
		err = asn1Error("asn1: wrong constructed flag: got ",
			bool2str(rcvrCons), ", want ", bool2str(assnCons))
	}
	return
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
