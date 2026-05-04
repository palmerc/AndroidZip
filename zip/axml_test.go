package zip_test

import (
	"encoding/binary"
	"testing"

	"github.com/palmerc/androidzip/zip"
)

// ── AXML byte builders ────────────────────────────────────────────────────────

// axmlBytes assembles a complete AXML file from the provided inner chunks.
// The outer XML wrapper chunk is written with the correct total file size.
func axmlBytes(chunkType uint16, innerChunks ...[]byte) []byte {
	var inner []byte
	for _, c := range innerChunks {
		inner = append(inner, c...)
	}
	totalSize := uint32(8 + len(inner))

	out := make([]byte, 8+len(inner))
	binary.LittleEndian.PutUint16(out[0:], chunkType)  // outer type
	binary.LittleEndian.PutUint16(out[2:], 8)           // headerSize
	binary.LittleEndian.PutUint32(out[4:], totalSize)
	copy(out[8:], inner)
	return out
}

// emptyStringPool builds a String Pool chunk with zero strings.
func emptyStringPool() []byte {
	const size = 28
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], 0x0001) // type
	binary.LittleEndian.PutUint16(b[2:], 0x001C) // headerSize = 28
	binary.LittleEndian.PutUint32(b[4:], size)   // chunkSize
	// stringCount=0, styleCount=0, flags=0
	binary.LittleEndian.PutUint32(b[20:], size) // stringsStart (no strings, points to chunk end)
	return b
}

// stringPoolWithCount builds a String Pool with an explicitly set stringCount
// and stringsStart, regardless of whether they are consistent.
func stringPoolWithCount(stringCount uint32, stringsStart uint32) []byte {
	// Make a chunk just large enough for the header; we won't add real strings.
	const size = 36 // header(28) + 2 dummy offset entries
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], 0x0001)
	binary.LittleEndian.PutUint16(b[2:], 0x001C)
	binary.LittleEndian.PutUint32(b[4:], size)
	binary.LittleEndian.PutUint32(b[8:], stringCount)  // inflated count
	binary.LittleEndian.PutUint32(b[20:], stringsStart) // where string data "starts"
	return b
}

// stringPoolWithDuplicateOffsets builds a String Pool with two strings that
// share the same offset in the offset table.
func stringPoolWithDuplicateOffsets() []byte {
	// 2 strings, both pointing to offset 0 in string data.
	// String data: one UTF-16LE "hi" = 0x03 0x00 'h' 0x00 'i' 0x00 (Android short form).
	stringData := []byte{0x03, 0x00, 'h', 0x00, 'i', 0x00}

	// offset table: two entries, both 0
	offsets := make([]byte, 8) // 2 × uint32(0)

	const headerSize = 28
	stringsStart := uint32(headerSize + len(offsets))
	chunkSize := uint32(int(stringsStart) + len(stringData))

	b := make([]byte, chunkSize)
	binary.LittleEndian.PutUint16(b[0:], 0x0001)
	binary.LittleEndian.PutUint16(b[2:], 0x001C)
	binary.LittleEndian.PutUint32(b[4:], chunkSize)
	binary.LittleEndian.PutUint32(b[8:], 2)           // stringCount = 2
	binary.LittleEndian.PutUint32(b[20:], stringsStart)
	copy(b[28:], offsets)                              // both offsets = 0
	copy(b[stringsStart:], stringData)
	return b
}

// chunkWithSize builds a minimal chunk of the given type and explicit size.
// Used to construct misaligned chunks.
func chunkWithSize(chunkType uint16, size uint32) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], chunkType)
	binary.LittleEndian.PutUint16(b[2:], 8) // headerSize
	binary.LittleEndian.PutUint32(b[4:], size)
	return b
}

// startElement builds a Start Element chunk with the given attributeStart and
// attributeSize values.
func startElement(attrStart, attrSize uint16) []byte {
	const size = 36
	b := make([]byte, size)
	binary.LittleEndian.PutUint16(b[0:], 0x0102) // type
	binary.LittleEndian.PutUint16(b[2:], 36)     // headerSize
	binary.LittleEndian.PutUint32(b[4:], size)
	// lineNumber=0, comment=0, ns=0, name=0
	binary.LittleEndian.PutUint16(b[24:], attrStart)
	binary.LittleEndian.PutUint16(b[26:], attrSize)
	return b
}

// ── helper: build an APK with the given bytes stored as AndroidManifest.xml ──

func apkWithManifest(manifestData []byte) []byte {
	name := []byte("AndroidManifest.xml")

	var buf []byte
	writeU32 := func(v uint32) { buf = append(buf, le32(v)...) }
	writeU16 := func(v uint16) { buf = append(buf, le16(v)...) }

	// LFH
	lfhOffset := uint32(len(buf))
	buf = append(buf, le32(0x04034b50)...)
	writeU16(20) // version needed
	writeU16(0)  // GPBF
	writeU16(0)  // compression: STORED
	writeU16(0)  // mod time
	writeU16(0)  // mod date
	writeU32(checksum(manifestData))
	writeU32(uint32(len(manifestData)))
	writeU32(uint32(len(manifestData)))
	writeU16(uint16(len(name)))
	writeU16(0) // extra len
	buf = append(buf, name...)
	buf = append(buf, manifestData...)

	// CDR
	cdOffset := uint32(len(buf))
	buf = append(buf, le32(0x02014b50)...)
	writeU16(20) // version made by
	writeU16(20) // version needed
	writeU16(0)  // GPBF
	writeU16(0)  // compression: STORED
	writeU16(0)  // mod time
	writeU16(0)  // mod date
	writeU32(checksum(manifestData))
	writeU32(uint32(len(manifestData)))
	writeU32(uint32(len(manifestData)))
	writeU16(uint16(len(name)))
	writeU16(0) // extra len
	writeU16(0) // comment len
	writeU16(0) // disk number start
	writeU16(0) // internal attrs
	writeU32(0) // external attrs
	writeU32(lfhOffset)
	buf = append(buf, name...)

	cdSize := uint32(len(buf)) - cdOffset

	// EOCD
	buf = append(buf, le32(0x06054b50)...)
	writeU16(0) // disk number
	writeU16(0) // CD start disk
	writeU16(1) // entries on disk
	writeU16(1) // total entries
	writeU32(cdSize)
	writeU32(cdOffset)
	writeU16(0) // comment len

	return buf
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestAXMLClean confirms that a well-formed AXML manifest produces no issues.
func TestAXMLClean(t *testing.T) {
	manifest := axmlBytes(0x0003, emptyStringPool())
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertNoIssues(t, entry.Issues)
}

// TestAXMLBadMagic: the outer chunk type byte is not 0x03.
// Android's ResXMLTree continues parsing; JADX and apktool abort.
func TestAXMLBadMagic(t *testing.T) {
	manifest := axmlBytes(0x0004, emptyStringPool()) // wrong outer type
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLBadMagic)
}

// TestAXMLStringCountMismatch: the declared string count implies an offset
// table that overlaps the string data region.
func TestAXMLStringCountMismatch(t *testing.T) {
	// stringsStart=28 means string data starts right after the header,
	// leaving no room for any string offset entries.
	// A count of 5 would need 20 bytes of offsets starting at byte 28,
	// which extends into and past the stringsStart boundary.
	pool := stringPoolWithCount(5, 28)
	manifest := axmlBytes(0x0003, pool)
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLStringCountMismatch)
}

// TestAXMLStringDuplicateOffset: two entries in the offset table point to
// the same position. Android silently accepts; analysis tools may collapse
// or error on the duplicate.
func TestAXMLStringDuplicateOffset(t *testing.T) {
	manifest := axmlBytes(0x0003, stringPoolWithDuplicateOffsets())
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLStringDuplicateOffset)
}

// TestAXMLChunkMisaligned: a chunk size is not a multiple of 4.
// All subsequent chunks are at wrong offsets for tools that enforce alignment.
func TestAXMLChunkMisaligned(t *testing.T) {
	// Build a String Pool chunk with size 29 (not divisible by 4).
	pool := chunkWithSize(0x0001, 29)
	// Pad to a multiple of 4 so the outer file size is sensible,
	// but the chunk's declared size is still 29.
	pool = append(pool, 0x00, 0x00, 0x00) // padding not counted in chunk size

	manifest := axmlBytes(0x0003, pool)
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLChunkMisaligned)
}

// TestAXMLAttributeSizeInvalid: attributeSize is 0x18 (24) instead of 0x14 (20).
// Tools that hard-code 20 bytes per attribute misread every attribute in the element.
func TestAXMLAttributeSizeInvalid(t *testing.T) {
	manifest := axmlBytes(0x0003,
		emptyStringPool(),
		startElement(0x0014, 0x0018), // attrStart=20 (ok), attrSize=24 (bad)
	)
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLAttributeSizeInvalid)
}

// TestAXMLAttributeStartInvalid: attributeStart is 0x18 (24) instead of 0x14 (20).
// Tools that assume the standard start offset locate attributes at the wrong position.
func TestAXMLAttributeStartInvalid(t *testing.T) {
	manifest := axmlBytes(0x0003,
		emptyStringPool(),
		startElement(0x0018, 0x0014), // attrStart=24 (bad), attrSize=20 (ok)
	)
	apk := apkWithManifest(manifest)
	archive := mustOpen(t, apk)

	entry := entryNamed(t, archive.Entries, "AndroidManifest.xml")
	if entry == nil {
		return
	}
	assertHasIssue(t, entry.Issues, zip.IssueAXMLAttributeStartInvalid)
}
