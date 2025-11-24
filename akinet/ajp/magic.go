package ajp

import (
	"github.com/levoai/observability-shared-libs/memview"
)

var (
	ajpBinaryMagic = []byte{0x12, 0x34}
	ajpAsciiMagic  = []byte{0x41, 0x42}
	ajpMagics      = [][]byte{
		ajpBinaryMagic,
		ajpAsciiMagic,
	}

	// ajpMagic is kept for compatibility with legacy helpers that assume the
	// binary prefix.
	ajpMagic = ajpBinaryMagic
)

func findAJPMagic(input memview.MemView, start int64) (idx int64, magic []byte) {
	bestIdx := int64(-1)
	var matched []byte
	for _, candidate := range ajpMagics {
		if candidateIdx := input.Index(start, candidate); candidateIdx >= 0 {
			if bestIdx == -1 || candidateIdx < bestIdx {
				bestIdx = candidateIdx
				matched = candidate
			}
		}
	}
	return bestIdx, matched
}

func matchAJPMagicAt(input memview.MemView, offset int64) bool {
	if input.Len() < offset+2 {
		return false
	}
	first := input.GetByte(offset)
	second := input.GetByte(offset + 1)
	for _, magic := range ajpMagics {
		if first == magic[0] && second == magic[1] {
			return true
		}
	}
	return false
}

func hasPartialAJPMagic(input memview.MemView, searchStart int64) bool {
	if input.Len()-searchStart != 1 {
		return false
	}
	last := input.GetByte(input.Len() - 1)
	for _, magic := range ajpMagics {
		if last == magic[0] {
			return true
		}
	}
	return false
}
