package percent

import (
	"github.com/go-directory/common"
)

/*
Encode returns an instance of []byte alongside an error following
an attempt to manually percent-encode the input value.
*/
func Encode(s []byte) (enc []byte, err error) {
	out := make([]byte, 0, len(s)*3)

	hex := "0123456789ABCDEF"

	for _, b := range s {
		// Unreserved bytes: A–Z, a–z, 0–9, '-', '.', '_', '~'
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			(b >= '0' && b <= '9') || b == '-' || b == '.' ||
			b == '_' || b == '~' {
			out = append(out, b)
			continue
		}

		// Percent-encode
		out = append(out, '%')
		out = append(out, hex[b>>4])
		out = append(out, hex[b&0x0F])
	}

	return out, nil
}

/*
Decode returns an instance of []byte alongside an error following
an attempt to manually decode the percent-encoded sequence in the
input value.

For every '%' followed by two valid hexadecimal digits, the sequence
is replaced by the corresponding byte.
*/
func Decode(enc []byte) (dec []byte, err error) {
	L := len(enc)
	out := make([]byte, 0, L)

	i := 0
	for i < L {
		if enc[i] != '%' {
			out = append(out, enc[i])
			i++
			continue
		}

		if i+2 >= L {
			return nil, encodingError("percent encoding: incomplete sequence")
		}

		b1 := enc[i+1]
		b2 := enc[i+2]

		upperHex := func(a byte) bool { return 'A' <= a && a <= 'F' }
		lowerHex := func(a byte) bool { return 'a' <= a && a <= 'f' }
		digitHex := func(a byte) bool { return '0' <= a && a <= '9' }

		var v1, v2 byte

		switch {
		case digitHex(b1):
			v1 = b1 - '0'
		case upperHex(b1):
			v1 = b1 - 'A' + 10
		case lowerHex(b1):
			v1 = b1 - 'a' + 10
		default:
			return nil, encodingError("percent encoding: invalid: \"", string([]byte{b1, b2}), "\"")
		}

		switch {
		case digitHex(b2):
			v2 = b2 - '0'
		case upperHex(b2):
			v2 = b2 - 'A' + 10
		case lowerHex(b2):
			v2 = b2 - 'a' + 10
		default:
			return nil, encodingError("percent encoding: invalid: \"", string([]byte{b1, b2}), "\"")
		}

		out = append(out, (v1<<4)|v2)
		i += 3
	}

	return out, nil
}

func encodingError(msg ...string) error {
	return common.LDAPResultOther.New(msg...)
}
