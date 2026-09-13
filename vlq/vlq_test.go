package vlq

import (
	"math/big"
	"testing"
)

func TestVLQ_int64RoundTrip(t *testing.T) {
	for idx, integer := range []int64{
		int64(4372),
		int64(-87374),
	} {
		enc := Encode[int64](integer)
		var p int
		dec, err := Decode[int64](enc, &p)
		if err != nil {
			t.Fatalf("%s[%d] VLQ decode failed: %v", t.Name(), idx, err)
		} else if dec != integer {
			t.Fatalf("%s[%d] VLQ decode failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, dec)
		}
	}
}

func TestVLQ_uint64RoundTrip(t *testing.T) {
	for idx, integer := range []uint64{
		uint64(4372),
		uint64(87374),
	} {
		enc := Encode[uint64](integer)
		var p int
		dec, err := Decode[uint64](enc, &p)
		if err != nil {
			t.Fatalf("%s[%d] VLQ decode failed: %v", t.Name(), idx, err)
		} else if dec != integer {
			t.Fatalf("%s[%d] VLQ decode failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, dec)
		}
	}
}

func TestVLQ_bigIntRoundTrip(t *testing.T) {
	one := new(big.Int).SetUint64(437223789)
	two := new(big.Int).SetInt64(-4432372)
	three, _ := new(big.Int).SetString(`987895962269883002155146617097157934`, 10)
	for idx, integer := range []*big.Int{
		one,
		two,
		three,
	} {
		enc := Encode[*big.Int](integer)

		var p int
		dec, err := Decode[*big.Int](enc, &p)
		if err != nil {
			t.Fatalf("%s[%d] VLQ decode failed: %v", t.Name(), idx, err)
		} else if dec.(*big.Int).Cmp(integer) != 0 {
			t.Fatalf("%s[%d] VLQ decode failed:\n\twant: %d\n\tgot:  %d",
				t.Name(), idx, integer, dec)
		}
	}
}
