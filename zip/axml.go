package zip

import "fmt"

// AXML (binary AndroidManifest.xml) chunk types.
// AOSP: platform/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h
const (
	axmlChunkStringPool   = uint16(0x0001)
	axmlChunkResourceMap  = uint16(0x0002)
	axmlChunkXML          = uint16(0x0003)
	axmlChunkStartNS      = uint16(0x0100)
	axmlChunkEndNS        = uint16(0x0101)
	axmlChunkStartElement = uint16(0x0102)
	axmlChunkEndElement   = uint16(0x0103)
	axmlChunkCData        = uint16(0x0104)
)

// Expected values for Start Element attribute fields.
// ResXMLTree_attrExt is 20 bytes, so attributes follow at offset 20 from
// the start of that struct; each ResXMLTree_attribute is also 20 bytes.
const (
	axmlExpectedAttributeStart = uint16(0x0014) // 20 bytes
	axmlExpectedAttributeSize  = uint16(0x0014) // 20 bytes
)

// ParseAXML checks binary XML data (AXML format) for the structural
// malformations used by Android malware to evade analysis tools.
//
// AXML is the binary representation of AndroidManifest.xml stored inside APKs.
// Android's PackageManager (via ResXMLTree) is lenient about many of these
// fields; analysis tools (JADX, apktool) apply stricter validation and fail.
//
// AOSP: platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, ResXMLTree
func ParseAXML(data []byte) []Issue {
	if len(data) < 8 {
		return nil
	}

	var issues []Issue

	// ── Outer XML chunk header ────────────────────────────────────────────────
	// Bytes 0-1: chunk type (must be 0x0003 for a well-formed manifest).
	// Bytes 2-3: header size (always 8 for the outer wrapper).
	// Bytes 4-7: total file size.
	outerType := ru16(data, 0)
	if outerType != axmlChunkXML {
		issues = append(issues, Issue{
			Kind:     IssueAXMLBadMagic,
			CDValue:  fmt.Sprintf("0x%04x", outerType),
			LFHValue: fmt.Sprintf("0x%04x", axmlChunkXML),
		})
		// Continue — Android's ResXMLTree does not abort on a bad magic byte
		// in all code paths; some versions proceed and parse the inner chunks.
	}

	outerSize := int(ru32(data, 4))
	if outerSize > len(data) {
		outerSize = len(data)
	}

	// ── Inner chunk walk ──────────────────────────────────────────────────────
	pos := 8
	for pos+8 <= outerSize {
		chunkType := ru16(data, pos)
		chunkSize := int(ru32(data, pos+4))

		if chunkSize < 8 {
			break // malformed: minimum chunk is 8 bytes
		}
		if pos+chunkSize > outerSize {
			break // chunk extends past file boundary
		}

		// Every chunk must be 4-byte aligned.
		// Unaligned chunks shift all subsequent chunk positions, causing
		// parsers to lose their place in the stream.
		if chunkSize%4 != 0 {
			issues = append(issues, Issue{
				Kind:    IssueAXMLChunkMisaligned,
				CDValue: fmt.Sprintf("type=0x%04x offset=%d size=%d", chunkType, pos, chunkSize),
			})
		}

		chunk := data[pos : pos+chunkSize]

		switch chunkType {
		case axmlChunkStringPool:
			issues = append(issues, parseAXMLStringPool(chunk)...)
		case axmlChunkStartElement:
			issues = append(issues, parseAXMLStartElement(chunk)...)
		}

		pos += chunkSize
	}

	return issues
}

// parseAXMLStringPool validates the String Pool chunk.
//
// String Pool layout (all little-endian, offsets from chunk start):
//   0  type        uint16 = 0x0001
//   2  headerSize  uint16
//   4  chunkSize   uint32
//   8  stringCount uint32  ← validated
//  12  styleCount  uint32
//  16  flags       uint32
//  20  stringsStart uint32 ← offset to string data (from chunk start)
//  24  stylesStart  uint32
//  28  offsets[stringCount] uint32  ← validated for duplicates and bounds
//
// AOSP: ResourceTypes.cpp, ResStringPool::uninit / setTo()
func parseAXMLStringPool(chunk []byte) []Issue {
	if len(chunk) < 28 {
		return nil
	}

	var issues []Issue

	stringCount := int(ru32(chunk, 8))
	stringsStart := int(ru32(chunk, 20))

	// The offset table for all declared strings starts at byte 28 and occupies
	// stringCount×4 bytes.  If that range overlaps or exceeds stringsStart, the
	// declared count is impossible — string offsets would alias string data.
	offsetTableEnd := 28 + stringCount*4
	if stringsStart > 0 && offsetTableEnd > stringsStart {
		issues = append(issues, Issue{
			Kind: IssueAXMLStringCountMismatch,
			CDValue: fmt.Sprintf(
				"stringCount=%d requires offset table [28,%d) but stringsStart=%d",
				stringCount, offsetTableEnd, stringsStart),
		})
		return issues // offset table is unreliable; skip per-entry checks
	}
	if offsetTableEnd > len(chunk) {
		issues = append(issues, Issue{
			Kind: IssueAXMLStringCountMismatch,
			CDValue: fmt.Sprintf(
				"stringCount=%d requires %d bytes, chunk is only %d bytes",
				stringCount, offsetTableEnd, len(chunk)),
		})
		return issues
	}

	// Validate each string offset: must be within the string data region and
	// must not duplicate a previously seen offset.
	stringDataSize := len(chunk) - stringsStart
	if stringsStart >= len(chunk) {
		return issues
	}

	seen := make(map[uint32]int) // offset → first index
	for i := 0; i < stringCount; i++ {
		off := ru32(chunk, 28+i*4)
		if int(off) >= stringDataSize {
			issues = append(issues, Issue{
				Kind:    IssueAXMLOffsetOutOfBounds,
				CDValue: fmt.Sprintf("string[%d] offset=%d >= stringDataSize=%d", i, off, stringDataSize),
			})
			continue
		}
		if prev, dup := seen[off]; dup {
			issues = append(issues, Issue{
				Kind:    IssueAXMLStringDuplicateOffset,
				CDValue: fmt.Sprintf("string[%d] and string[%d] share offset=%d", prev, i, off),
			})
		} else {
			seen[off] = i
		}
	}

	return issues
}

// parseAXMLStartElement validates attribute fields in a Start Element chunk.
//
// Start Element layout (offsets from chunk start):
//   0  type           uint16 = 0x0102
//   2  headerSize     uint16
//   4  chunkSize      uint32
//   8  lineNumber     uint32
//  12  comment        int32
//  16  ns             int32   (namespace URI string index)
//  20  name           int32   (element name string index)
//  24  attributeStart uint16  ← must be 0x0014 (20)
//  26  attributeSize  uint16  ← must be 0x0014 (20)
//  28  attributeCount uint16
//  30  idIndex        uint16
//  32  classIndex     uint16
//  34  styleIndex     uint16
//
// AOSP: ResourceTypes.h, ResXMLTree_attrExt; ResourceTypes.cpp, ResXMLTree::nextNode()
func parseAXMLStartElement(chunk []byte) []Issue {
	if len(chunk) < 36 {
		return nil
	}

	var issues []Issue

	attrStart := ru16(chunk, 24)
	attrSize := ru16(chunk, 26)

	if attrStart != axmlExpectedAttributeStart {
		issues = append(issues, Issue{
			Kind:     IssueAXMLAttributeStartInvalid,
			CDValue:  fmt.Sprintf("0x%04x", attrStart),
			LFHValue: fmt.Sprintf("0x%04x", axmlExpectedAttributeStart),
		})
	}
	if attrSize != axmlExpectedAttributeSize {
		issues = append(issues, Issue{
			Kind:     IssueAXMLAttributeSizeInvalid,
			CDValue:  fmt.Sprintf("0x%04x", attrSize),
			LFHValue: fmt.Sprintf("0x%04x", axmlExpectedAttributeSize),
		})
	}

	return issues
}

// ── byte reading helpers (bounds-checked, no panics) ─────────────────────────

func ru16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return uint16(b[off]) | uint16(b[off+1])<<8
}

func ru32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}
