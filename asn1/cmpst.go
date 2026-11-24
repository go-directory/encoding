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
	noTruncate ...bool,
) ([]byte, error) {

	t, payload, err := ReadConstructedTLV(enc, p, noTruncate...)
	if err == nil {
		err = t.Expect(class, true, tag)
	}

	return payload, err
}

/*
UnwrapTLV returns an instance of []byte alongside an error following an
attempt to traverse the provided encoding according to the parameters in
the input variadic [Tag] instances.

Each [Tag] processes a single "layer" of the encoded structure. If there
are three [Tag] instances input, this function attempts to traverse the
same number of layers. The data encountered at the last layer is the
return payload.

This is merely a convenience function written to simply calls to the
[ReadExpectedConstructedTLV] function in iterative fashion.

See also [WrapTLV].
*/
func UnwrapTLV(enc []byte, tags ...Tag) ([]byte, error) {
	var err error
	L := len(enc)
	if L == 0 {
		err = asn1Error("UnwrapTLV: empty input payload")
		emitErr(err)
		return nil, err
	}

	cur := enc
	p := 0

	for i := 0; i < len(tags) && err == nil; i++ {
		want := tags[i]

		emitT("asn1.UnwrapTLV[iter:%d]: class:%d, "+
			"tag:%d, curs:%d, rem:%d",
			i, want.Class, want.Tag, p, len(cur))

		var payload []byte
		if want.Constructed {
			// constructed TLV
			if payload, err = ReadExpectedConstructedTLV(cur, &p, want.Class, want.Tag); err == nil {
				cur = payload
				p = 0
				emitT("asn1.UnwrapTLV[iter:%d,recurse:ECTLV]: class:%d, "+
					"tag:%d, curs:0 [reset], rem:%d",
					i, want.Class, want.Tag, len(cur))
			}
		} else {
			if payload, err = ReadExpectedPrimitiveTLV(cur, &p, want.Class, want.Tag); err == nil {
				cur = payload
				p = 0
				emitT("asn1.UnwrapTLV[iter:%d,recurse:EPTLV]: class:%d, "+
					"tag:%d, curs:0 [reset], rem:%d",
					i, want.Class, want.Tag, len(cur))
			}
		}
	}
	emitT("asn1.UnwrapTLV: done, err:%t", err != nil)
	emitErr(err)

	return cur, nil
}

/*
WrapTLV returns a []byte instance alongside an error following an
attempt to wrap the input buf value using the input [Tag] variadic
for structural guidance.

See also [UnwrapTLV].
*/
func WrapTLV(buf []byte, tags ...Tag) ([]byte, error) {
	L := len(tags)
	if L == 0 {
		err := asn1Error("WrapTLV: no Tags found")
		emitErr(err)
		return nil, err
	}

	cur := buf
	for i := 0; i < L; i++ {
		t := tags[i]
		emitT("asn1.WrapTLV[iter:%d]: class:%d, tag:%d, rem:%d",
			i, t.Class, t.Tag, len(cur))

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
	emitErr(err)

	return
}

func expectClass(rcvrClass, assnClass byte) (err error) {
	if rcvrClass != assnClass {
		err = asn1Error("asn1: wrong class: got ",
			itoa(int(rcvrClass)), ", want ",
			itoa(int(assnClass)))
	}
	emitErr(err)

	return
}

func expectTag(rcvrTag, assnTag uint32) (err error) {
	if rcvrTag != assnTag {
		err = asn1Error("asn1: wrong tag: got ",
			itoa(int(rcvrTag)), ", want ",
			itoa(int(assnTag)))
	}
	emitErr(err)

	return
}

func expectConstructed(rcvrCons, assnCons bool) (err error) {
	if rcvrCons != assnCons {
		err = asn1Error("asn1: wrong constructed flag: got ",
			bool2str(rcvrCons), ", want ", bool2str(assnCons))
		emitErr(err)
	}
	return
}

func WriteConstructedTLV(dst []byte, class byte, constructed bool, tagNum uint32, payload []byte) []byte {
	emitT("asn1.WriteConstructedTLV: class:%d, tag:%d, rem:%d",
		int(class), tagNum, len(payload))
	dst = WriteTag(dst, class, constructed, tagNum)
	dst = WriteLength(dst, len(payload))
	return append(dst, payload...)
}

/*
ReadConstructedTLV returns an instance of [Tag] and []byte alongside an error following an attempt
to read the header of the buf payload starting at position p.  The return [Tag] instance will bear
the class, tag and constructed values, while the out ([]byte) instance bears the actual bare value,
and does not include the class, tag and constructed byte. This is the default behavior.

The variadic noTruncate argument, when true, will NOT truncate the return out ([]byte) value of its
class, tag and constructed byte.
*/
func ReadConstructedTLV(buf []byte, p *int, noTruncate ...bool) (head Tag, out []byte, err error) {
	if *p >= len(buf) {
		emitErr(errEOF)
		return head, nil, errEOF
	}

	start := *p // remember tag start

	head, ok := ReadTag(buf[*p:])
	if ok {
		emitT("asn1.ReadConstructedTLV: class:%d, tag:%d, "+
			"curs:%d", int(head.Class), head.Tag, *p)

		*p++

		length, n := ReadLength(buf[*p:])
		emitT("asn1.ReadConstructedTLV: class:%d, tag:%d, "+
			"curs:%d", int(head.Class), head.Tag, *p)
		if n == 0 {
			err = errLength
			emitErr(err)
			return
		}
		*p += n

		if length > 0 {

			if *p+length > len(buf) {
				err = errEOF
				emitErr(err)
				return
			}

			out = buf[*p : *p+length]

			// advance cursor past payload
			*p += length

			// optional -- return full TLV (Tag + Length + Payload)
			if len(noTruncate) > 0 && noTruncate[0] {
				out = buf[start:*p]
			}
			emitT("asn1.ReadConstructedTLV: class:%d, tag:%d, "+
				"curs:%d [reset], len:%d", int(head.Class),
				head.Tag, *p, len(out))
		}
	} else {
		err = errEOF
		emitErr(err)
	}

	return
}
