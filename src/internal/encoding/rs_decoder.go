package encoding

import (
	"errors"
	"runtime"

	"github.com/Picocrypt/infectious"
)

// RSDecoder owns mutable single-codeword scratch. It must not be shared between
// concurrent operations. Close clears the owned correction bytes; it does not
// clear the caller's input or destination.
type RSDecoder struct {
	codec    *infectious.FEC
	shares   []infectious.Share
	codeword []byte
	parity   [1]byte
}

// NewRSDecoder allocates operation-owned scratch for complete codewords.
func NewRSDecoder(codec *infectious.FEC) *RSDecoder {
	decoder := &RSDecoder{codec: codec, shares: make([]infectious.Share, codec.Total()), codeword: make([]byte, codec.Total())}
	for number := range decoder.shares {
		decoder.shares[number] = infectious.Share{Number: number, Data: decoder.codeword[number : number+1]}
	}
	return decoder
}

// DecodeInto repairs unknown symbol errors and copies systematic bytes into
// destination. Valid RS128 words are checked by recomputing their eight parity
// bytes with the same codec; only invalid words require Correct. The input is
// preserved because Correct mutates and reorders shares. Input and destination
// must not overlap.
func (decoder *RSDecoder) DecodeInto(destination, encoded []byte) error {
	codec := decoder.codec
	if len(encoded) != codec.Total() || len(destination) != codec.Required() {
		return errors.New("rs decode: invalid input or destination size")
	}
	if codec.Required() == RS128DataSize && codec.Total() == RS128EncodedSize {
		valid := true
		for number := codec.Required(); number < codec.Total(); number++ {
			if err := codec.EncodeSingle(encoded[:codec.Required()], decoder.parity[:], number); err != nil {
				return err
			}
			if decoder.parity[0] != encoded[number] {
				valid = false
				break
			}
		}
		if valid {
			copy(destination, encoded[:codec.Required()])
			return nil
		}
	}
	copy(decoder.codeword, encoded)
	// Restore the canonical mapping on every word: Correct may reorder shares.
	for number := range decoder.shares {
		decoder.shares[number] = infectious.Share{Number: number, Data: decoder.codeword[number : number+1]}
	}
	if err := codec.Correct(decoder.shares); err != nil {
		return err
	}
	for _, share := range decoder.shares {
		if share.Number < codec.Required() {
			destination[share.Number] = share.Data[0]
		}
	}
	return nil
}

func (decoder *RSDecoder) Close() {
	if decoder == nil {
		return
	}
	clear(decoder.codeword)
	clear(decoder.parity[:])
	runtime.KeepAlive(decoder)
}
