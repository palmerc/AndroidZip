package zip_test

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/palmerc/androidzip/zip"
)

// ── binary helpers ────────────────────────────────────────────────────────────

func le16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
func le64(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

func u16p(v uint16) *uint16 { return &v }
func u32p(v uint32) *uint32 { return &v }

func checksum(data []byte) uint32 { return crc32.ChecksumIEEE(data) }

// zip64Extra builds a ZIP64 extended information extra field (ID 0x0001).
// Pass nil for fields that should not appear in the block.
func zip64Extra(uncompSize, compSize, lfhOffset *uint64) []byte {
	var data bytes.Buffer
	if uncompSize != nil {
		data.Write(le64(*uncompSize))
	}
	if compSize != nil {
		data.Write(le64(*compSize))
	}
	if lfhOffset != nil {
		data.Write(le64(*lfhOffset))
	}
	var out bytes.Buffer
	out.Write(le16(0x0001))
	out.Write(le16(uint16(data.Len())))
	out.Write(data.Bytes())
	return out.Bytes()
}

// ── archive builder ───────────────────────────────────────────────────────────

// entrySpec describes one file in a test archive.
// Zero/nil values for CD fields inherit the corresponding LFH value.
type entrySpec struct {
	name string
	data []byte

	// LFH fields
	lfhGPBF        uint16
	lfhCompression uint16
	lfhCRC32       *uint32 // nil = computed from data
	lfhCompSize    *uint32 // nil = len(data)
	lfhUncompSize  *uint32 // nil = len(data)
	lfhName        string  // empty = name
	lfhExtra       []byte

	// CD overrides (nil = same as LFH)
	cdGPBF        *uint16
	cdCompression *uint16
	cdCRC32       *uint32
	cdCompSize    *uint32
	cdUncompSize  *uint32
	cdName        string  // empty = s.name
	cdNameBytes   []byte  // non-nil overrides cdName with raw bytes (for invalid UTF-8 tests)
	cdLFHOffset   *uint32
	cdExtra       []byte
}

type archiveBuilder struct{ entries []entrySpec }

func (ab *archiveBuilder) add(e entrySpec) { ab.entries = append(ab.entries, e) }

func (ab *archiveBuilder) build() []byte {
	var buf bytes.Buffer

	type pending struct {
		spec      entrySpec
		lfhOffset uint32
	}
	var pend []pending

	for _, s := range ab.entries {
		lfhOffset := uint32(buf.Len())

		lfhName := s.lfhName
		if lfhName == "" {
			lfhName = s.name
		}
		nameBytes := []byte(lfhName)

		compSize := uint32(len(s.data))
		if s.lfhCompSize != nil {
			compSize = *s.lfhCompSize
		}
		uncompSize := uint32(len(s.data))
		if s.lfhUncompSize != nil {
			uncompSize = *s.lfhUncompSize
		}
		crc := checksum(s.data)
		if s.lfhCRC32 != nil {
			crc = *s.lfhCRC32
		}

		buf.Write(le32(0x04034b50))
		buf.Write(le16(20))
		buf.Write(le16(s.lfhGPBF))
		buf.Write(le16(s.lfhCompression))
		buf.Write(le16(0)) // mod time
		buf.Write(le16(0)) // mod date
		buf.Write(le32(crc))
		buf.Write(le32(compSize))
		buf.Write(le32(uncompSize))
		buf.Write(le16(uint16(len(nameBytes))))
		buf.Write(le16(uint16(len(s.lfhExtra))))
		buf.Write(nameBytes)
		buf.Write(s.lfhExtra)
		buf.Write(s.data)

		pend = append(pend, pending{s, lfhOffset})
	}

	cdOffset := uint32(buf.Len())

	for _, p := range pend {
		s := p.spec

		cdName := s.cdName
		if cdName == "" {
			cdName = s.name // CD defaults to canonical name, not lfhName
		}
		cdNameBytes := []byte(cdName)
		if s.cdNameBytes != nil {
			cdNameBytes = s.cdNameBytes
		}

		gpbf := s.lfhGPBF
		if s.cdGPBF != nil {
			gpbf = *s.cdGPBF
		}
		compression := s.lfhCompression
		if s.cdCompression != nil {
			compression = *s.cdCompression
		}
		compSize := uint32(len(s.data))
		if s.lfhCompSize != nil {
			compSize = *s.lfhCompSize
		}
		if s.cdCompSize != nil {
			compSize = *s.cdCompSize
		}
		uncompSize := uint32(len(s.data))
		if s.lfhUncompSize != nil {
			uncompSize = *s.lfhUncompSize
		}
		if s.cdUncompSize != nil {
			uncompSize = *s.cdUncompSize
		}
		crc := checksum(s.data)
		if s.lfhCRC32 != nil {
			crc = *s.lfhCRC32
		}
		if s.cdCRC32 != nil {
			crc = *s.cdCRC32
		}
		lfhOffset := p.lfhOffset
		if s.cdLFHOffset != nil {
			lfhOffset = *s.cdLFHOffset
		}

		buf.Write(le32(0x02014b50))
		buf.Write(le16(20)) // version made by
		buf.Write(le16(20)) // version needed
		buf.Write(le16(gpbf))
		buf.Write(le16(compression))
		buf.Write(le16(0)) // mod time
		buf.Write(le16(0)) // mod date
		buf.Write(le32(crc))
		buf.Write(le32(compSize))
		buf.Write(le32(uncompSize))
		buf.Write(le16(uint16(len(cdNameBytes))))
		buf.Write(le16(uint16(len(s.cdExtra))))
		buf.Write(le16(0)) // comment length
		buf.Write(le16(0)) // disk number start
		buf.Write(le16(0)) // internal attrs
		buf.Write(le32(0)) // external attrs
		buf.Write(le32(lfhOffset))
		buf.Write(cdNameBytes)
		buf.Write(s.cdExtra)
	}

	cdSize := uint32(buf.Len()) - cdOffset
	count := uint16(len(ab.entries))

	buf.Write(le32(0x06054b50))
	buf.Write(le16(0)) // disk number
	buf.Write(le16(0)) // CD start disk
	buf.Write(le16(count))
	buf.Write(le16(count))
	buf.Write(le32(cdSize))
	buf.Write(le32(cdOffset))
	buf.Write(le16(0)) // comment length

	return buf.Bytes()
}

// ── assertion helpers ─────────────────────────────────────────────────────────

func mustOpen(t *testing.T, data []byte) *zip.Archive {
	t.Helper()
	archive, err := zip.OpenReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	return archive
}

func entryNamed(t *testing.T, entries []*zip.Entry, name string) *zip.Entry {
	t.Helper()
	for _, e := range entries {
		if e.Name == name {
			return e
		}
	}
	t.Errorf("no entry named %q", name)
	return nil
}

func assertHasIssue(t *testing.T, issues []zip.Issue, kind zip.IssueKind) {
	t.Helper()
	for _, i := range issues {
		if i.Kind == kind {
			return
		}
	}
	t.Errorf("expected issue %v; got %v", kind, issueKinds(issues))
}

func assertNoIssues(t *testing.T, issues []zip.Issue) {
	t.Helper()
	if len(issues) > 0 {
		t.Errorf("expected no issues; got %v", issueKinds(issues))
	}
}

func issueKinds(issues []zip.Issue) []zip.IssueKind {
	ks := make([]zip.IssueKind, len(issues))
	for i, iss := range issues {
		ks[i] = iss.Kind
	}
	return ks
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestClean verifies that a well-formed single-entry archive produces no issues.
func TestClean(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{name: "classes.dex", data: []byte("dex\n035")})
	archive := mustOpen(t, ab.build())

	assertNoIssues(t, archive.ArchiveIssues)
	if e := entryNamed(t, archive.Entries, "classes.dex"); e != nil {
		assertNoIssues(t, e.Issues)
	}
}

// TestEncryptionMismatch_CDSet: Central Directory has the encryption flag set,
// Local File Header does not. Tools reading the CD refuse to extract; Android
// reads the LFH flag and extracts normally.
func TestEncryptionMismatch_CDSet(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:    "classes.dex",
		data:    []byte("dex\n035"),
		lfhGPBF: 0x0000,
		cdGPBF:  u16p(0x0001), // encryption bit set in CD only
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueEncryptionMismatch)
	assertHasIssue(t, e.Issues, zip.IssueGPBFMismatch)
}

// TestEncryptionMismatch_LFHSet: Local File Header has the encryption flag set,
// Central Directory does not. Tools reading the LFH prompt for a non-existent
// password; Android reads the CD flag and extracts normally.
func TestEncryptionMismatch_LFHSet(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:    "classes.dex",
		data:    []byte("dex\n035"),
		lfhGPBF: 0x0001, // encryption bit set in LFH only
		cdGPBF:  u16p(0x0000),
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueEncryptionMismatch)
	assertHasIssue(t, e.Issues, zip.IssueGPBFMismatch)
}

// TestUnsupportedCompression: compression method is not STORED or DEFLATED.
// Android defaults to STORED; analysis tools throw an exception.
func TestUnsupportedCompression(t *testing.T) {
	const unknownMethod = uint16(9) // BZIP2 — not supported by Android

	var ab archiveBuilder
	ab.add(entrySpec{
		name:           "classes.dex",
		data:           []byte("dex\n035"),
		lfhCompression: unknownMethod,
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueUnsupportedCompression)
}

// TestCompressionMismatch: CD and LFH disagree on the compression method.
// Tools that read the LFH will decompress with the wrong algorithm.
func TestCompressionMismatch(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:           "classes.dex",
		data:           []byte("dex\n035"),
		lfhCompression: 0, // STORED
		cdCompression:  u16p(8), // DEFLATED
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueCompressionMismatch)
}

// TestDuplicateName: two Central Directory entries share the same filename.
// Android loads the last one; tools that use the first entry see a decoy.
func TestDuplicateName(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{name: "classes.dex", data: []byte("decoy dex")})
	ab.add(entrySpec{name: "classes.dex", data: []byte("real dex")})
	archive := mustOpen(t, ab.build())

	count := 0
	for _, e := range archive.Entries {
		if e.Name == "classes.dex" {
			assertHasIssue(t, e.Issues, zip.IssueDuplicateName)
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 entries named classes.dex, got %d", count)
	}
}

// TestDirectoryFileConflict: a directory entry "classes.dex/" and a file entry
// "classes.dex" coexist. Extraction tools attempt to create a directory at the
// file's path; Android finds the file entry via the CD hash table.
func TestDirectoryFileConflict(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{name: "classes.dex/", data: nil})  // directory
	ab.add(entrySpec{name: "classes.dex", data: []byte("dex\n035")})
	archive := mustOpen(t, ab.build())

	for _, e := range archive.Entries {
		assertHasIssue(t, e.Issues, zip.IssueDirectoryFileConflict)
	}
}

// TestCRC32Mismatch: CRC-32 differs between CD and LFH.
// Android trusts the CD value; tools validating against the LFH may reject
// the file or report a spurious integrity error.
func TestCRC32Mismatch(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:     "classes.dex",
		data:     []byte("dex\n035"),
		lfhCRC32: u32p(0xDEADBEEF),
		cdCRC32:  u32p(0x12345678),
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueCRC32Mismatch)
}

// TestCompressedSizeMismatch: compressed size differs between CD and LFH.
// A falsified LFH size can cause tools to read into adjacent entries.
func TestCompressedSizeMismatch(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:        "classes.dex",
		data:        []byte("dex\n035"),
		lfhCompSize: u32p(7),
		cdCompSize:  u32p(999),
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueCompressedSizeMismatch)
}

// TestUncompressedSizeMismatch: uncompressed size differs between CD and LFH.
func TestUncompressedSizeMismatch(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:          "classes.dex",
		data:          []byte("dex\n035"),
		lfhUncompSize: u32p(7),
		cdUncompSize:  u32p(1024),
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueUncompressedSizeMismatch)
}

// TestNameMismatch: the filename in the LFH differs from the one in the CD.
// Sequential LFH scanners index the entry under the wrong name.
func TestNameMismatch(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:    "classes.dex", // CD name (also used as entry.Name)
		data:    []byte("dex\n035"),
		lfhName: "classes_decoy.dex", // LFH name
	})
	archive := mustOpen(t, ab.build())

	// Entry.Name comes from the CD.
	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueNameMismatch)
}

// TestLFHOffsetOutOfRange: the LFH offset in the CD points past end of file.
func TestLFHOffsetOutOfRange(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{
		name:        "classes.dex",
		data:        []byte("dex\n035"),
		cdLFHOffset: u32p(0xFFFFFF00), // well past any test file
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueLFHOffsetOutOfRange)
}

// TestZIP64SentinelMismatch: the CD uses the 0xFFFFFFFF sentinel (with a ZIP64
// extra field carrying the real size) while the LFH carries the actual value
// in its 32-bit field. Tools that trust the LFH see a wildly different size.
func TestZIP64SentinelMismatch(t *testing.T) {
	const actualSize = uint64(7)
	const sentinel = uint32(0xFFFFFFFF)

	u64 := actualSize
	var ab archiveBuilder
	ab.add(entrySpec{
		name:          "classes.dex",
		data:          []byte("dex\n035"),
		lfhUncompSize: u32p(uint32(actualSize)), // LFH: real value in 32-bit field
		cdUncompSize:  u32p(sentinel),           // CD: sentinel
		cdExtra:       zip64Extra(&u64, nil, nil), // ZIP64 extra carries real size
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "classes.dex")
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueZIP64SentinelMismatch)
}

// TestZIP64EOCDMismatch: a ZIP64 EOCD and the ZIP32 EOCD point to different
// Central Directories. Android uses the ZIP64 EOCD (real CD); tools without
// ZIP64 support use the ZIP32 EOCD and see the decoy CD.
//
// Layout:
//
//	[LFH + data: "decoy.dex"]
//	[LFH + data: "classes.dex"]
//	[Decoy CD]   ← ZIP32 EOCD CDOffset
//	[Real CD]    ← ZIP64 EOCD CDOffset
//	[ZIP64 EOCD]
//	[ZIP64 EOCD Locator]
//	[ZIP32 EOCD]
func TestZIP64EOCDMismatch(t *testing.T) {
	var buf bytes.Buffer

	decoyData := []byte("decoy payload")
	realData := []byte("dex\n035")

	// ── file data ────────────────────────────────────────────────────────────

	decoyLFHOffset := uint32(buf.Len())
	writeLFH(&buf, "decoy.dex", decoyData)

	realLFHOffset := uint32(buf.Len())
	writeLFH(&buf, "classes.dex", realData)

	// ── decoy Central Directory ───────────────────────────────────────────────

	decoyCDOffset := uint32(buf.Len())
	writeCDR(&buf, "decoy.dex", decoyData, decoyLFHOffset)
	decoyCDSize := uint32(buf.Len()) - decoyCDOffset

	// ── real Central Directory ────────────────────────────────────────────────

	realCDOffset := uint32(buf.Len())
	writeCDR(&buf, "classes.dex", realData, realLFHOffset)
	realCDSize := uint32(buf.Len()) - realCDOffset

	// ── ZIP64 EOCD ────────────────────────────────────────────────────────────

	zip64EOCDOffset := uint64(buf.Len())
	buf.Write(le32(0x06064b50))      // signature
	buf.Write(le64(44))              // record size (bytes after this field)
	buf.Write(le16(45))              // version made by
	buf.Write(le16(45))              // version needed
	buf.Write(le32(0))               // disk number
	buf.Write(le32(0))               // CD start disk
	buf.Write(le64(1))               // entries on this disk
	buf.Write(le64(1))               // total entries
	buf.Write(le64(uint64(realCDSize)))
	buf.Write(le64(uint64(realCDOffset)))

	// ── ZIP64 EOCD Locator ────────────────────────────────────────────────────

	buf.Write(le32(0x07064b50)) // signature
	buf.Write(le32(0))          // disk with ZIP64 EOCD
	buf.Write(le64(zip64EOCDOffset))
	buf.Write(le32(1)) // total disks

	// ── ZIP32 EOCD (points to decoy CD) ──────────────────────────────────────

	buf.Write(le32(0x06054b50))
	buf.Write(le16(0)) // disk number
	buf.Write(le16(0)) // CD start disk
	buf.Write(le16(1)) // entries on disk
	buf.Write(le16(1)) // total entries
	buf.Write(le32(decoyCDSize))
	buf.Write(le32(decoyCDOffset)) // ← different from ZIP64 EOCD
	buf.Write(le16(0))             // comment length

	archive := mustOpen(t, buf.Bytes())

	// Archive-level issue: the two EOCDs disagree on the CD location.
	assertHasIssue(t, archive.ArchiveIssues, zip.IssueZIP64EOCDMismatch)

	// Android uses the ZIP64 EOCD, so the real entry is visible.
	_ = entryNamed(t, archive.Entries, "classes.dex")
}

// ── low-level write helpers for TestZIP64EOCDMismatch ────────────────────────

func writeLFH(buf *bytes.Buffer, name string, data []byte) {
	nameBytes := []byte(name)
	buf.Write(le32(0x04034b50))
	buf.Write(le16(20))
	buf.Write(le16(0))                           // GPBF
	buf.Write(le16(0))                           // compression (STORED)
	buf.Write(le16(0))                           // mod time
	buf.Write(le16(0))                           // mod date
	buf.Write(le32(checksum(data)))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le16(uint16(len(nameBytes))))
	buf.Write(le16(0)) // extra length
	buf.Write(nameBytes)
	buf.Write(data)
}

func writeCDR(buf *bytes.Buffer, name string, data []byte, lfhOffset uint32) {
	nameBytes := []byte(name)
	buf.Write(le32(0x02014b50))
	buf.Write(le16(20)) // version made by
	buf.Write(le16(20)) // version needed
	buf.Write(le16(0))  // GPBF
	buf.Write(le16(0))  // compression (STORED)
	buf.Write(le16(0))  // mod time
	buf.Write(le16(0))  // mod date
	buf.Write(le32(checksum(data)))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le16(uint16(len(nameBytes))))
	buf.Write(le16(0)) // extra length
	buf.Write(le16(0)) // comment length
	buf.Write(le16(0)) // disk number start
	buf.Write(le16(0)) // internal attrs
	buf.Write(le32(0)) // external attrs
	buf.Write(le32(lfhOffset))
	buf.Write(nameBytes)
}
