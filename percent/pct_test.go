package percent

import (
	"bytes"
	"fmt"
	"testing"
)

func ExampleEncode_roundTrip() {
	raw := []byte(`ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(cn=John Doe)?!x-foo=bar,!x-bar`)

	enc, err := Encode(raw)
	if err != nil {
		fmt.Println(err)
		return
	}

	var dec []byte
	if dec, err = Decode(enc); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("raw matches decoded value: %t", bytes.Equal(raw, dec))
	// Output: raw matches decoded value: true
}

func TestCodec(t *testing.T) {
	for idx, raw := range percentRawTestValues {
		enc, err := Encode(raw)
		if err != nil {
			t.Errorf("%s[%d] encode failed: %v", t.Name(), idx, err)
		}
		var dec []byte
		if dec, err = Decode(enc); err != nil {
			t.Errorf("%s[%d] decode failed: %v", t.Name(), idx, err)
		}
		if !bytes.Equal(raw, dec) {
			t.Errorf("%s[%d] decode failed:\n\rwant: %s\n\tgot:  %s",
				t.Name(), idx, string(raw), string(dec))
		}
	}

	for idx, raw := range percentBogusTestValues {
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s[%d] check failed (%s): want error, got nil",
				t.Name(), idx, string(raw))
		}
	}
}

var percentRawTestValues = [][]byte{
	// Common ASCII
	[]byte("hello"),
	[]byte("HelloWorld123"),
	[]byte("simple-test"),
	[]byte("with_underscores"),
	[]byte("dots.and.more.dots"),
	[]byte("UPPERlowerMIXED"),

	// Spaces and punctuation
	[]byte("a b c"),
	[]byte("one,two;three:four"),
	[]byte("email@example.com"),
	[]byte("path/to/resource"),
	[]byte("query=param&other=value"),

	// UTF‑8 multibyte
	[]byte("café"),
	[]byte("naïve"),
	[]byte("こんにちは"),
	[]byte("😀 emoji test 😀"),

	// Control characters
	[]byte("line1\nline2"),
	[]byte("tab\tseparated"),
	[]byte("carriage\rreturn"),

	// Mixed raw + characters that *would* be encoded
	[]byte("raw%percent"),
	[]byte("50% complete"),
	[]byte("100% legit"),
	[]byte("%a0"),

	[]byte("%b1"),
	[]byte("%B1"),
	[]byte("%c2"),
	[]byte("%d3"),
	[]byte("%e4"),
	[]byte("%E4"),
	[]byte("%f5"),
	[]byte("%0a"),
	[]byte("%1b"),
	[]byte("%2c"),
	[]byte("%3d"),
	[]byte("%4e"),
	[]byte("%5f"),
	[]byte("%20"),
	[]byte("%41"),
	[]byte("%7e"),
	[]byte("ok%20now"),

	// Edge cases
	[]byte(""),
	[]byte("%"),            // incomplete percent sequence
	[]byte("%%"),           // double percent, still incomplete
	[]byte("%A"),           // incomplete hex pair
	[]byte("%%%"),          // multiple incomplete
	[]byte("end%2"),        // incomplete at end
	[]byte("weird%GG"),     // invalid hex
	[]byte("ok%20now"),     // valid percent sequence (space)
	[]byte("mix%20and%ZZ"), // valid then invalid
	[]byte(`ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(cn=John Doe)?!x-foo=bar,!x-bar`),
	[]byte(`sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<yypsdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<sdrerldriodr8seriisu3gwoh892uhjifjsiojgiowejigpwigy-h#892gh3p928huu3fhuf3>:>:>:>P:P)O((OU&Y&TGRFEDRTYHIK<<L<L<`),
}

var percentBogusTestValues = [][]byte{
	// percent encoding: incomplete sequence (i+2 >= L)
	[]byte("%"),    // length 1 → triggers incomplete
	[]byte("%A"),   // length 2 → still incomplete
	[]byte("end%"), // incomplete at end
	[]byte("x%1"),  // incomplete hex pair

	// b1 invalid -> default case (invalid hex)
	[]byte("%G0"), // 'G' invalid for b1
	[]byte("%Z1"), // 'Z' invalid for b1
	[]byte("%!2"), // punctuation invalid
	[]byte("% 3"), // space invalid

	// b2 invalid -> default case (invalid hex)
	[]byte("%0G"), // 'G' invalid for b2
	[]byte("%1Z"), // 'Z' invalid for b2
	[]byte("%2!"), // punctuation invalid
	[]byte("%3 "), // space invalid
}
