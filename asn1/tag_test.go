package asn1

import (
	"fmt"
)

func ExampleReadTag() {
	// A fake UNIVERSAL SEQUENCE
	payload := []byte{0x30, 0x0, 0x0, 0x0}
	tag, ok := ReadTag(payload)
	if ok {
		fmt.Printf("Class:          %d\n", tag.Class)
		fmt.Printf("Is constructed: %t\n", tag.Constructed)
		fmt.Printf("Tag:            %d\n", tag.Tag)
	}
	// Output:
	// Class:          0
	// Is constructed: true
	// Tag:            16
}
