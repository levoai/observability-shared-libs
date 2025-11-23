package ajp

import (
	"github.com/google/gopacket/reassembly"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/buffer_pool"
	"github.com/akitasoftware/akita-libs/memview"
)

// Returns a factory for parsing AJP requests (web server -> app server).
func NewAJPRequestParserFactory(pool buffer_pool.BufferPool) akinet.TCPParserFactory {
	return ajpRequestParserFactory{pool: pool}
}

// Returns a factory for parsing AJP responses (app server -> web server).
func NewAJPResponseParserFactory(pool buffer_pool.BufferPool) akinet.TCPParserFactory {
	return ajpResponseParserFactory{pool: pool}
}

type ajpRequestParserFactory struct {
	pool buffer_pool.BufferPool
}

func (f ajpRequestParserFactory) Name() string {
	return "AJP Request Parser Factory"
}

func (f ajpRequestParserFactory) Accepts(input memview.MemView, isEnd bool) (akinet.AcceptDecision, int64) {
	return acceptAJP(input, isEnd, ajpRequestEntryTypes)
}

func (f ajpRequestParserFactory) CreateParser(id akinet.TCPBidiID, seq, ack reassembly.Sequence) akinet.TCPParser {
	return newAJPParser(true, id, seq, ack, f.pool)
}

type ajpResponseParserFactory struct {
	pool buffer_pool.BufferPool
}

func (f ajpResponseParserFactory) Name() string {
	return "AJP Response Parser Factory"
}

func (f ajpResponseParserFactory) Accepts(input memview.MemView, isEnd bool) (akinet.AcceptDecision, int64) {
	return acceptAJP(input, isEnd, ajpResponseEntryTypes)
}

func (f ajpResponseParserFactory) CreateParser(id akinet.TCPBidiID, seq, ack reassembly.Sequence) akinet.TCPParser {
	return newAJPParser(false, id, seq, ack, f.pool)
}

var ajpRequestEntryTypes = map[byte]struct{}{
	ajpForwardRequestType: {},
}

var ajpResponseEntryTypes = map[byte]struct{}{
	ajpSendHeadersType:   {},
	ajpSendBodyChunkType: {},
	ajpGetBodyChunkType:  {},
	ajpEndResponseType:   {},
}

func acceptAJP(input memview.MemView, isEnd bool, allowed map[byte]struct{}) (akinet.AcceptDecision, int64) {
	searchStart := int64(0)

	for {
		if input.Len()-searchStart < int64(len(ajpMagic)) {
			if isEnd {
				return akinet.Reject, input.Len()
			}
			return akinet.NeedMoreData, searchStart
		}

		idx := input.Index(searchStart, ajpMagic)
		if idx < 0 {
			if isEnd {
				return akinet.Reject, input.Len()
			}
			// Preserve a potential partial prefix at the end.
			if input.Len()-searchStart == 1 && input.GetByte(input.Len()-1) == ajpMagic[0] {
				return akinet.NeedMoreData, input.Len() - 1
			}
			return akinet.NeedMoreData, searchStart
		}

		if input.Len() < idx+4 {
			if isEnd {
				return akinet.Reject, input.Len()
			}
			return akinet.NeedMoreData, idx
		}

		length := int64(input.GetUint16(idx + 2))
		total := idx + 4 + length
		if input.Len() < total {
			if isEnd {
				return akinet.Reject, input.Len()
			}
			return akinet.NeedMoreData, idx
		}

		msgType := input.GetByte(idx + 4)
		if _, ok := allowed[msgType]; ok {
			return akinet.Accept, idx
		}

		// Skip this message and continue scanning.
		searchStart = total
		if searchStart >= input.Len() {
			if isEnd {
				return akinet.Reject, input.Len()
			}
			return akinet.NeedMoreData, searchStart
		}
	}
}
