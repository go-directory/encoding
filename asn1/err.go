package asn1

import (
	"errors"
	"io"

	"github.com/go-directory/common"
)

type commonErr = common.Error

var (
	errEOF    error = io.ErrUnexpectedEOF
	errCodec        = errors.New("asn1: unable to process encoding; bogus payload")
	errLength       = errors.New("asn1: bad encoding length")
)

func asn1Error(msg ...string) (err commonErr) {
	err = common.ErrorASN1.New(msg...)
	err.SetHeader("ASN.1:")
	return
}

func bool2str(b bool) (s string) {
	if s = "false"; b {
		s = "true"
	}

	return
}
