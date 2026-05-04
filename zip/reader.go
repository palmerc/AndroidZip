package zip

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
)

// Archive holds the parsed result of a ZIP/APK file.
type Archive struct {
	EOCD          EndOfCentralDirectory
	ZIP64EOCD     *ZIP64EOCD   // non-nil for archives that use ZIP64 extensions
	SigningBlock  *SigningBlock // non-nil when an APK Signing Block is present
	Comment       []byte
	Entries       []*Entry
	ArchiveIssues []Issue // structural issues not tied to a single entry
}

// OpenReader parses r as a ZIP archive using Android-faithful rules:
//   - ZIP64 EOCD takes priority over ZIP32 EOCD when both are present
//   - Central Directory is the authoritative source for the entry table
//   - Both CD and LFH are read for every entry so discrepancies are visible
//   - Duplicate names are preserved (last-wins is Android's behaviour)
func OpenReader(r io.ReadSeeker) (*Archive, error) {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek end: %w", err)
	}

	eocd, eocdOffset, comment, err := findEOCD(r, size)
	if err != nil {
		return nil, err
	}

	z64eocd, archiveIssues, err := findZIP64EOCD(r, eocdOffset, eocd)
	if err != nil {
		return nil, err
	}

	// Determine effective CD parameters.
	// Android's libziparchive uses ZIP64 EOCD values when present.
	// AOSP: system/libziparchive/zip_archive.cc, OpenArchiveInternal()
	cdOffset := int64(eocd.CDOffset)
	entryCount := int(eocd.CDEntriesTotal)
	if z64eocd != nil {
		cdOffset = int64(z64eocd.CDOffset)
		entryCount = int(z64eocd.CDEntriesTotal)
	}

	sigBlock, sigIssues, err := FindSigningBlock(r, cdOffset)
	if err != nil {
		return nil, fmt.Errorf("signing block: %w", err)
	}
	archiveIssues = append(archiveIssues, sigIssues...)

	entries, err := readCentralDirectory(r, cdOffset, entryCount)
	if err != nil {
		return nil, err
	}

	if err := readLocalHeaders(r, size, entries); err != nil {
		return nil, err
	}

	detectDuplicates(entries)
	detectDirectoryConflicts(entries)
	auditFilenames(entries)
	analyzeManifest(r, entries)

	return &Archive{
		EOCD:          eocd,
		ZIP64EOCD:     z64eocd,
		SigningBlock:  sigBlock,
		Comment:       comment,
		Entries:       entries,
		ArchiveIssues: archiveIssues,
	}, nil
}

// findEOCD scans backward from EOF for the End of Central Directory record.
// It handles arbitrarily long ZIP comments, which malware uses to shift
// where tools locate the EOCD.
func findEOCD(r io.ReadSeeker, size int64) (EndOfCentralDirectory, int64, []byte, error) {
	searchSize := int64(eocdSearchSize)
	if searchSize > size {
		searchSize = size
	}

	buf := make([]byte, searchSize)
	if _, err := r.Seek(size-searchSize, io.SeekStart); err != nil {
		return EndOfCentralDirectory{}, 0, nil, fmt.Errorf("seek for EOCD: %w", err)
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return EndOfCentralDirectory{}, 0, nil, fmt.Errorf("read EOCD search area: %w", err)
	}

	sig := []byte{0x50, 0x4b, 0x05, 0x06}
	for i := len(buf) - eocdFixedSize; i >= 0; i-- {
		if !bytes.Equal(buf[i:i+4], sig) {
			continue
		}
		var rec EndOfCentralDirectory
		if err := binary.Read(bytes.NewReader(buf[i:]), order, &rec); err != nil {
			continue
		}
		commentStart := i + eocdFixedSize
		commentEnd := commentStart + int(rec.CommentLen)
		if commentEnd > len(buf) {
			continue
		}
		comment := make([]byte, rec.CommentLen)
		copy(comment, buf[commentStart:commentEnd])
		offset := size - searchSize + int64(i)
		return rec, offset, comment, nil
	}
	return EndOfCentralDirectory{}, 0, nil, fmt.Errorf("EOCD not found")
}

// findZIP64EOCD looks for a ZIP64 EOCD locator immediately before the regular
// EOCD and, if found, reads the ZIP64 EOCD it points to.
//
// It also checks for discrepancies between the ZIP32 and ZIP64 EOCDs, which
// is a known attack where different parsers navigate to different Central
// Directories based on which EOCD they trust.
//
// AOSP: system/libziparchive/zip_archive.cc, OpenArchiveInternal()
func findZIP64EOCD(r io.ReadSeeker, eocdOffset int64, eocd EndOfCentralDirectory) (*ZIP64EOCD, []Issue, error) {
	locatorOffset := eocdOffset - zip64EOCDLocatorSize
	if locatorOffset < 0 {
		return nil, nil, nil
	}

	if _, err := r.Seek(locatorOffset, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek ZIP64 locator: %w", err)
	}

	var loc ZIP64EOCDLocator
	if err := binary.Read(r, order, &loc); err != nil || loc.Signature != sigEOCD64Locator {
		return nil, nil, nil // not a ZIP64 archive
	}

	if _, err := r.Seek(int64(loc.EOCD64Offset), io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek ZIP64 EOCD: %w", err)
	}

	var z64 ZIP64EOCD
	if err := binary.Read(r, order, &z64); err != nil {
		return nil, nil, fmt.Errorf("read ZIP64 EOCD: %w", err)
	}
	if z64.Signature != sigEOCD64 {
		return nil, nil, fmt.Errorf("bad ZIP64 EOCD signature: %#x", z64.Signature)
	}

	// Detect ZIP32/ZIP64 EOCD split: if both carry non-sentinel CD offset
	// or entry count values that disagree, different parsers will navigate
	// to different Central Directories.
	var issues []Issue
	if eocd.CDOffset != sentinel32 && uint64(eocd.CDOffset) != z64.CDOffset {
		issues = append(issues, Issue{
			Kind:     IssueZIP64EOCDMismatch,
			CDValue:  fmt.Sprintf("ZIP32 CD offset=%#x", eocd.CDOffset),
			LFHValue: fmt.Sprintf("ZIP64 CD offset=%#x", z64.CDOffset),
		})
	}
	if eocd.CDEntriesTotal != sentinel16 && uint64(eocd.CDEntriesTotal) != z64.CDEntriesTotal {
		issues = append(issues, Issue{
			Kind:     IssueZIP64EOCDMismatch,
			CDValue:  fmt.Sprintf("ZIP32 entry count=%d", eocd.CDEntriesTotal),
			LFHValue: fmt.Sprintf("ZIP64 entry count=%d", z64.CDEntriesTotal),
		})
	}

	return &z64, issues, nil
}

// readCentralDirectory reads all Central Directory records starting at cdOffset.
func readCentralDirectory(r io.ReadSeeker, cdOffset int64, entryCount int) ([]*Entry, error) {
	if _, err := r.Seek(cdOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek CD: %w", err)
	}

	entries := make([]*Entry, 0, entryCount)
	for i := 0; i < entryCount; i++ {
		e, err := readCDRecord(r)
		if err != nil {
			return entries, fmt.Errorf("CD entry %d: %w", i, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func readCDRecord(r io.ReadSeeker) (*Entry, error) {
	var rec CentralDirectoryRecord
	if err := binary.Read(r, order, &rec); err != nil {
		return nil, err
	}
	if rec.Signature != sigCDR {
		return nil, fmt.Errorf("bad CD signature: %#x", rec.Signature)
	}

	name := make([]byte, rec.NameLen)
	if _, err := io.ReadFull(r, name); err != nil {
		return nil, fmt.Errorf("read CD name: %w", err)
	}
	extra := make([]byte, rec.ExtraLen)
	if _, err := io.ReadFull(r, extra); err != nil {
		return nil, fmt.Errorf("read CD extra: %w", err)
	}
	comment := make([]byte, rec.CommentLen)
	if _, err := io.ReadFull(r, comment); err != nil {
		return nil, fmt.Errorf("read CD comment: %w", err)
	}

	z64 := parseZIP64Extra(extra, rec.UncompressedSize, rec.CompressedSize, rec.LFHOffset, rec.DiskNumberStart)

	// Resolve LFH offset: use ZIP64 extra value when the 32-bit field is sentinel.
	lfhOffset := int64(rec.LFHOffset)
	if rec.LFHOffset == sentinel32 && z64 != nil && z64.LFHOffset != nil {
		lfhOffset = int64(*z64.LFHOffset)
	}

	return &Entry{
		Name:      string(name),
		CD:        rec,
		CDName:    name,
		CDExtra:   extra,
		CDZIP64:   z64,
		LFHOffset: lfhOffset,
	}, nil
}

// readLocalHeaders performs Pass 2: seek to each LFH, read it, and diff
// against the paired CD record.
func readLocalHeaders(r io.ReadSeeker, fileSize int64, entries []*Entry) error {
	for _, e := range entries {
		if e.LFHOffset >= fileSize {
			e.Issues = append(e.Issues, Issue{
				Kind:    IssueLFHOffsetOutOfRange,
				CDValue: e.LFHOffset,
			})
			continue
		}

		if _, err := r.Seek(e.LFHOffset, io.SeekStart); err != nil {
			return fmt.Errorf("seek LFH for %q: %w", e.Name, err)
		}

		var lfh LocalFileHeader
		if err := binary.Read(r, order, &lfh); err != nil {
			return fmt.Errorf("read LFH for %q: %w", e.Name, err)
		}

		if lfh.Signature != sigLFH {
			e.Issues = append(e.Issues, Issue{
				Kind:     IssueLFHSignatureBad,
				LFHValue: lfh.Signature,
			})
		}

		lfhName := make([]byte, lfh.NameLen)
		if _, err := io.ReadFull(r, lfhName); err != nil {
			return fmt.Errorf("read LFH name for %q: %w", e.Name, err)
		}
		lfhExtra := make([]byte, lfh.ExtraLen)
		if _, err := io.ReadFull(r, lfhExtra); err != nil {
			return fmt.Errorf("read LFH extra for %q: %w", e.Name, err)
		}

		// LFH ZIP64 extra only carries sizes, not LFH offset or disk start.
		z64 := parseZIP64Extra(lfhExtra, lfh.UncompressedSize, lfh.CompressedSize, 0, 0)

		e.LFH = lfh
		e.LFHName = lfhName
		e.LFHExtra = lfhExtra
		e.LFHZIP64 = z64
		e.DataOffset = e.LFHOffset + lfhFixedSize + int64(lfh.NameLen) + int64(lfh.ExtraLen)

		diffEntries(e)
	}
	return nil
}

// parseZIP64Extra scans the extra field blob for a ZIP64 extended information
// block (ID 0x0001) and parses whichever fields are present.
//
// Per the ZIP spec, a field is included in the ZIP64 extra block only when the
// corresponding field in the main header carries a sentinel value. Pass 0 for
// lfhOffset and diskStart when parsing an LFH extra field (those fields are
// never present in LFH context).
func parseZIP64Extra(extra []byte, uncompSize, compSize, lfhOffset uint32, diskStart uint16) *ZIP64ExtraField {
	for i := 0; i+4 <= len(extra); {
		id := order.Uint16(extra[i:])
		sz := int(order.Uint16(extra[i+2:]))
		i += 4
		if i+sz > len(extra) {
			break
		}
		if id == zip64ExtraID {
			return parseZIP64Block(extra[i:i+sz], uncompSize, compSize, lfhOffset, diskStart)
		}
		i += sz
	}
	return nil
}

func parseZIP64Block(data []byte, uncompSize, compSize, lfhOffset uint32, diskStart uint16) *ZIP64ExtraField {
	r := bytes.NewReader(data)
	z := &ZIP64ExtraField{}

	read64 := func() (uint64, bool) {
		var v uint64
		return v, binary.Read(r, order, &v) == nil
	}
	read32 := func() (uint32, bool) {
		var v uint32
		return v, binary.Read(r, order, &v) == nil
	}

	if uncompSize == sentinel32 {
		if v, ok := read64(); ok {
			z.UncompressedSize = &v
		}
	}
	if compSize == sentinel32 {
		if v, ok := read64(); ok {
			z.CompressedSize = &v
		}
	}
	if lfhOffset == sentinel32 {
		if v, ok := read64(); ok {
			z.LFHOffset = &v
		}
	}
	if diskStart == sentinel16 {
		if v, ok := read32(); ok {
			z.DiskStart = &v
		}
	}

	return z
}

// effectiveUncompressedSize returns the resolved uncompressed size for an
// entry header, expanding ZIP64 sentinel values using the extra field.
func effectiveUncompressedSize(reg uint32, z *ZIP64ExtraField) uint64 {
	if reg == sentinel32 && z != nil && z.UncompressedSize != nil {
		return *z.UncompressedSize
	}
	return uint64(reg)
}

// effectiveCompressedSize returns the resolved compressed size for an
// entry header, expanding ZIP64 sentinel values using the extra field.
func effectiveCompressedSize(reg uint32, z *ZIP64ExtraField) uint64 {
	if reg == sentinel32 && z != nil && z.CompressedSize != nil {
		return *z.CompressedSize
	}
	return uint64(reg)
}

// diffEntries compares CD and LFH fields and appends Issues for any mismatch.
func diffEntries(e *Entry) {
	cd, lfh := e.CD, e.LFH

	// Encryption flag — most exploited bit
	cdEncrypted := cd.GPBF&GPBFEncrypted != 0
	lfhEncrypted := lfh.GPBF&GPBFEncrypted != 0
	if cdEncrypted != lfhEncrypted {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueEncryptionMismatch,
			CDValue:  cdEncrypted,
			LFHValue: lfhEncrypted,
		})
	}

	// Full GPBF comparison
	if cd.GPBF != lfh.GPBF {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueGPBFMismatch,
			CDValue:  cd.GPBF,
			LFHValue: lfh.GPBF,
		})
	}

	// Compression method
	if cd.Compression != lfh.Compression {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueCompressionMismatch,
			CDValue:  cd.Compression,
			LFHValue: lfh.Compression,
		})
	}

	// Unsupported compression in either header
	unsupported := func(m uint16) bool {
		return m != CompressionStored && m != CompressionDeflated
	}
	if unsupported(cd.Compression) || unsupported(lfh.Compression) {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueUnsupportedCompression,
			CDValue:  cd.Compression,
			LFHValue: lfh.Compression,
		})
	}

	// CRC-32
	if cd.CRC32 != lfh.CRC32 {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueCRC32Mismatch,
			CDValue:  cd.CRC32,
			LFHValue: lfh.CRC32,
		})
	}

	// Sizes — compare after ZIP64 expansion.
	// Guard on DataDescriptor: when bit 3 is set, LFH sizes are legitimately zero.
	if cd.GPBF&GPBFDataDescriptor == 0 {
		// Detect sentinel mismatch: one side uses ZIP64 extension, other doesn't.
		cdUncompSentinel := cd.UncompressedSize == sentinel32
		lfhUncompSentinel := lfh.UncompressedSize == sentinel32
		if cdUncompSentinel != lfhUncompSentinel {
			e.Issues = append(e.Issues, Issue{
				Kind:     IssueZIP64SentinelMismatch,
				CDValue:  fmt.Sprintf("uncompressed=0x%08x", cd.UncompressedSize),
				LFHValue: fmt.Sprintf("uncompressed=0x%08x", lfh.UncompressedSize),
			})
		}
		cdCompSentinel := cd.CompressedSize == sentinel32
		lfhCompSentinel := lfh.CompressedSize == sentinel32
		if cdCompSentinel != lfhCompSentinel {
			e.Issues = append(e.Issues, Issue{
				Kind:     IssueZIP64SentinelMismatch,
				CDValue:  fmt.Sprintf("compressed=0x%08x", cd.CompressedSize),
				LFHValue: fmt.Sprintf("compressed=0x%08x", lfh.CompressedSize),
			})
		}

		// Compare effective sizes (ZIP64-resolved).
		cdComp := effectiveCompressedSize(cd.CompressedSize, e.CDZIP64)
		lfhComp := effectiveCompressedSize(lfh.CompressedSize, e.LFHZIP64)
		if cdComp != lfhComp {
			e.Issues = append(e.Issues, Issue{
				Kind:     IssueCompressedSizeMismatch,
				CDValue:  cdComp,
				LFHValue: lfhComp,
			})
		}

		cdUncomp := effectiveUncompressedSize(cd.UncompressedSize, e.CDZIP64)
		lfhUncomp := effectiveUncompressedSize(lfh.UncompressedSize, e.LFHZIP64)
		if cdUncomp != lfhUncomp {
			e.Issues = append(e.Issues, Issue{
				Kind:     IssueUncompressedSizeMismatch,
				CDValue:  cdUncomp,
				LFHValue: lfhUncomp,
			})
		}
	}

	// Filename
	if !bytes.Equal(e.CDName, e.LFHName) {
		e.Issues = append(e.Issues, Issue{
			Kind:     IssueNameMismatch,
			CDValue:  string(e.CDName),
			LFHValue: string(e.LFHName),
		})
	}
}

// detectDuplicates flags entries whose names appear more than once.
// Android resolves duplicates last-wins; many analysis tools use first-wins.
// AOSP: system/libziparchive/zip_archive.cc, OpenArchiveInternal()
func detectDuplicates(entries []*Entry) {
	seen := make(map[string]int)
	for i, e := range entries {
		if j, ok := seen[e.Name]; ok {
			entries[j].Issues = append(entries[j].Issues, Issue{Kind: IssueDuplicateName})
			e.Issues = append(e.Issues, Issue{Kind: IssueDuplicateName})
		} else {
			seen[e.Name] = i
		}
	}
}

// detectDirectoryConflicts flags entries where a directory name matches a
// file entry name (e.g. "classes.dex/" vs "classes.dex").
func detectDirectoryConflicts(entries []*Entry) {
	fileNames := make(map[string]bool)
	dirNames := make(map[string]bool)

	for _, e := range entries {
		isDir := len(e.Name) > 0 && e.Name[len(e.Name)-1] == '/'
		if isDir {
			dirNames[e.Name[:len(e.Name)-1]] = true
		} else {
			fileNames[e.Name] = true
		}
	}

	for _, e := range entries {
		isDir := len(e.Name) > 0 && e.Name[len(e.Name)-1] == '/'
		base := e.Name
		if isDir {
			base = e.Name[:len(e.Name)-1]
		}
		if (isDir && fileNames[base]) || (!isDir && dirNames[base]) {
			e.Issues = append(e.Issues, Issue{Kind: IssueDirectoryFileConflict})
		}
	}
}

// analyzeManifest finds the AndroidManifest.xml entry Android would load
// (last entry with that name, per last-wins duplicate resolution) and runs
// AXML malformation detection on its decompressed content.
func analyzeManifest(r io.ReadSeeker, entries []*Entry) {
	var manifest *Entry
	for _, e := range entries {
		if e.Name == "AndroidManifest.xml" && canReadData(e) {
			manifest = e // last-wins, matching Android's behaviour
		}
	}
	if manifest == nil {
		return
	}
	data, err := readEntryData(r, manifest)
	if err != nil {
		return // can't decompress; ZIP-level issues already recorded
	}
	manifest.Issues = append(manifest.Issues, ParseAXML(data)...)
}

// canReadData reports whether an entry's data is safe to attempt reading.
// Entries with structural issues that invalidate the data offset or size
// cannot be safely decompressed.
func canReadData(e *Entry) bool {
	for _, issue := range e.Issues {
		switch issue.Kind {
		case IssueLFHOffsetOutOfRange, IssueLFHSignatureBad:
			return false
		}
	}
	return e.DataOffset > 0
}

// readEntryData seeks to the entry's data, reads the compressed bytes, and
// decompresses them using the compression method recorded in the Central
// Directory (Android's authoritative source).
func readEntryData(r io.ReadSeeker, e *Entry) ([]byte, error) {
	if _, err := r.Seek(e.DataOffset, io.SeekStart); err != nil {
		return nil, err
	}

	compSize := effectiveCompressedSize(e.CD.CompressedSize, e.CDZIP64)
	uncompSize := effectiveUncompressedSize(e.CD.UncompressedSize, e.CDZIP64)

	compressed := make([]byte, compSize)
	if _, err := io.ReadFull(r, compressed); err != nil {
		return nil, err
	}

	switch e.CD.Compression {
	case CompressionStored:
		return compressed, nil
	case CompressionDeflated:
		rc := flate.NewReader(bytes.NewReader(compressed))
		defer rc.Close()
		// LimitReader caps allocation if uncompSize is inflated.
		return io.ReadAll(io.LimitReader(rc, int64(uncompSize)+1))
	default:
		// Android treats unknown compression methods as STORED.
		return compressed, nil
	}
}
