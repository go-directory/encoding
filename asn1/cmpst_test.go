package asn1

import (
	"fmt"
	"testing"
)

func ExampleWrapTLV_sEQUENCE() {
	type SomeThing struct {
		Value  []byte
		Number int64
	}

	thing := SomeThing{}
	thing.Value = []byte("example1234")
	thing.Number = 444

	var enc []byte
	enc, err := EncodePrimitive(TagOctetString, thing.Value)
	if err != nil {
		fmt.Println(err)
		return
	}

	num := EncodeInteger[int64](thing.Number)
	if err != nil {
		fmt.Println(err)
		return
	}
	enc = append(enc, num...)

	enc, err = WrapTLV(enc, Tag{0, true, 16})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Encoded: %v\n", enc)

	var payload []byte
	payload, err = UnwrapTLV(enc, Tag{0, true, 16})
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec SomeThing

	p := 0
	dec.Value, err = ReadExpectedPrimitiveTLV(payload, &p, 0, 4, false) // ok to trim header
	if err != nil {
		fmt.Println(err)
		return
	}

	var intBytes []byte
	intBytes, err = ReadExpectedPrimitiveTLV(payload, &p, 0, 2, true) // do NOT trim header
	if err != nil {
		fmt.Println(err)
		return
	}

	dec.Number, err = DecodeInteger[int64](intBytes)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decoded: Value:%s, Number:%d\n", dec.Value, dec.Number)
	// Output:
	// Encoded: [48 17 4 11 101 120 97 109 112 108 101 49 50 51 52 2 2 1 188]
	// Decoded: Value:example1234, Number:444
}

func ExampleWrapTLV_roundTrip() {
	coreValue := []byte(`some encoded value`)
	tag := uint32(7) // or whatever your real tag is

	wrappedValue, err := WrapTLV(coreValue,
		Tag{ClassUniversal, true, uint32(TagSequence)},
		Tag{ClassContextSpecific, true, tag},
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	dec, err := UnwrapTLV(wrappedValue,
		Tag{ClassContextSpecific, true, tag},
		Tag{ClassUniversal, true, uint32(TagSequence)},
	)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%s", dec)
	// Output: some encoded value
}

func TestTagExpectSuccess(t *testing.T) {
	r := Tag{
		Class:       0,
		Constructed: true,
		Tag:         16,
	}

	if err := r.Expect(0, true, 16); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTagExpectWrongClass(t *testing.T) {
	r := Tag{
		Class:       1,
		Constructed: true,
		Tag:         16,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong class")
	}
}

func TestTagExpectWrongConstructed(t *testing.T) {
	r := Tag{
		Class:       0,
		Constructed: false,
		Tag:         16,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong constructed flag")
	}
}

func TestTagExpectWrongTag(t *testing.T) {
	r := Tag{
		Class:       0,
		Constructed: true,
		Tag:         5,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong tag")
	}
}

// TLV stuff on hold for now
/*
func TestTLVExpectSuccess(t *testing.T) {
	r := TLV{
		Class:       0,
		Constructed: true,
		Tag:         16, // byte -> uint32 cast must work
	}

	if err := r.Expect(0, true, 16); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTLVExpectWrongClass(t *testing.T) {
	r := TLV{
		Class:       2,
		Constructed: true,
		Tag:         16,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong class")
	}
}

func TestTLVExpectWrongConstructed(t *testing.T) {
	r := TLV{
		Class:       0,
		Constructed: false,
		Tag:         16,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong constructed flag")
	}
}

func TestTLVExpectWrongTag(t *testing.T) {
	r := TLV{
		Class:       0,
		Constructed: true,
		Tag:         5,
	}

	err := r.Expect(0, true, 16)
	if err == nil {
		t.Fatalf("expected error for wrong tag")
	}
}

func TestTLVExpectByteTagCastsCorrectly(t *testing.T) {
	r := TLV{
		Class:       0,
		Constructed: true,
		Tag:         byte(0x1F),
	}

	// 0x1F → uint32(31)
	if err := r.Expect(0, true, 31); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
*/
