package asn1

const (
	TagBoolean          byte = 0x01 // 1
	TagInteger          byte = 0x02 // 2
	TagBitString        byte = 0x03 // 3
	TagOctetString      byte = 0x04 // 4
	TagObjectIdentifier byte = 0x06 // 6
	TagEnumerated       byte = 0x0A // 10
	TagUTF8String       byte = 0x0c // 12
	TagSequence         byte = 0x10 // 16
	TagSet              byte = 0x11 // 17
	TagNumericString    byte = 0x12 // 18
	TagPrintableString  byte = 0x13 // 19
	TagT61String        byte = 0x14 // 20
	TagIA5String        byte = 0x16 // 22
	TagUniversalString  byte = 0x1C // 28
	TagBMPString        byte = 0x1E // 30
)

const (
	ClassUniversal       = 0
	ClassApplication     = 1
	ClassContextSpecific = 2
	ClassPrivate         = 3
)

/*
ReadTag is a convenience function meant to quickly return
class/tag/constructed information from the first byte of
the input value.

If the return ok value is false, the other return values
should not be evaluated.
*/
func ReadTag(enc []byte) (class byte, constructed bool, tag uint32, ok bool) {
	if ok = len(enc) > 0; ok {
		class = enc[0] >> 6
		constructed = (enc[0] & 0x20) != 0
		tag = uint32(enc[0] & 0x1F)
	}

	return
}
