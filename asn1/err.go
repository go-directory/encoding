package asn1

import (
	"errors"
	"io"

	"github.com/go-directory/common"
)

var (
	errEOF    error = io.ErrUnexpectedEOF
	errCodec        = errors.New("asn1: unable to process encoding; bogus payload")
	errLength       = errors.New("asn1: bad encoding length")
)

func asn1Error(msg ...string) error {
        m := append([]string{"ASN.1 "}, msg...)
        return common.ErrorASN1.New(m...)
}

func bool2str(b bool) (s string) {
	if s = "false"; b {
		s = "true"
	}

	return
}
