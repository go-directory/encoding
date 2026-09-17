package asn1

import (
	"math/big"
	"testing"
)

func TestInteger_int(t *testing.T) {
	for idx, integer := range []int{
		int(-37465),
		int(34728432),
	} {
		enc := EncodeInteger(integer)
		out, err := DecodeInteger[int](enc)
		if err != nil {
			t.Fatalf("%s[%d] failed: %v", t.Name(), idx, err)
		}
		if out != integer {
			t.Fatalf("%s[%d] failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, out)
		}
	}
}

func TestInteger_int64(t *testing.T) {
	for idx, integer := range []int64{
		int64(-37465),
		int64(34728432),
	} {
		enc := EncodeInteger(integer)
		out, err := DecodeInteger[int64](enc)
		if err != nil {
			t.Fatalf("%s[%d] failed: %v", t.Name(), idx, err)
		}
		if out != integer {
			t.Fatalf("%s[%d] failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, out)
		}
	}
}

func TestInteger_uint(t *testing.T) {
	for idx, integer := range []uint{
		uint(2174893284),
		uint(34728432),
	} {
		enc := EncodeInteger(integer)
		out, err := DecodeInteger[uint](enc)
		if err != nil {
			t.Fatalf("%s[%d] failed: %v", t.Name(), idx, err)
		}
		if out != integer {
			t.Fatalf("%s[%d] failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, out)
		}
	}
}

func TestInteger_uint64(t *testing.T) {
	for idx, integer := range []uint64{
		uint64(37465),
		uint64(34728432),
	} {
		enc := EncodeInteger(integer)
		out, err := DecodeInteger[uint64](enc)
		if err != nil {
			t.Fatalf("%s[%d] failed: %v", t.Name(), idx, err)
		}
		if out != integer {
			t.Fatalf("%s[%d] failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, out)
		}
	}
}

func TestInteger_bigInt(t *testing.T) {
	for idx, integer := range []*big.Int{
		new(big.Int).SetUint64(32782823),
		new(big.Int).SetInt64(-43883892),
	} {
		enc := EncodeInteger(integer)
		out, err := DecodeInteger[*big.Int](enc)
		if err != nil {
			t.Fatalf("%s[%d] failed: %v", t.Name(), idx, err)
		}
		if out.Cmp(integer) != 0 {
			t.Fatalf("%s[%d] failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, out)
		}
	}
}
