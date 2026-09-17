package asn1

import (
	"fmt"
	"testing"
)

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
		Tag{ClassUniversal, true, uint32(TagSequence)},
		Tag{ClassContextSpecific, true, tag},
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

func TestTLVExpectSuccess(t *testing.T) {
	r := TLV{
		Class:       0,
		Constructed: true,
		Tag:         16, // byte → uint32 cast must work
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
