package asn1

import (
	"errors"
	"io"
)

var (
	errEOF    error = io.ErrUnexpectedEOF
	errCodec        = errors.New("asn1: unable to process encoding; bogus payload")
	errLength       = errors.New("asn1: bad encoding length")
)
