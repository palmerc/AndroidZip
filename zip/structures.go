// Package zip implements Android-faithful ZIP parsing for APK analysis.
// It reads both Local File Headers and Central Directory entries for every
// entry, exposing discrepancies that standard tools hide.
package zip

import "encoding/binary"

// Signatures
const (
	sigLFH           uint32 = 0x04034b50
	sigDD            uint32 = 0x08074b50
	sigCDR           uint32 = 0x02014b50
	sigEOCD          uint32 = 0x06054b50
	sigEOCD64Locator uint32 = 0x07064b50
	sigEOCD64        uint32 = 0x06064b50
)

// Sentinel values signal that the real value is in the ZIP64 extra field.
const (
	sentinel32 uint32 = 0xFFFFFFFF
	sentinel16 uint16 = 0xFFFF
)

// zip64ExtraID is the extra field header ID for ZIP64 extended information.
const zip64ExtraID uint16 = 0x0001

// GPBF (General Purpose Bit Flag) bits
const (
	GPBFEncrypted      uint16 = 1 << 0
	GPBFDataDescriptor uint16 = 1 << 3
	GPBFStrongEncrypt  uint16 = 1 << 6
	GPBFUTF8           uint16 = 1 << 11
)

// CompressionMethod values Android recognises natively.
// Any other value is treated as Stored by libziparchive.
const (
	CompressionStored   uint16 = 0
	CompressionDeflated uint16 = 8
)

var order = binary.LittleEndian

// LocalFileHeader is the per-entry header immediately preceding file data.
// ZIP spec section 4.3.7.
type LocalFileHeader struct {
	Signature        uint32 // 0x04034b50
	VersionNeeded    uint16
	GPBF             uint16
	Compression      uint16
	LastModTime      uint16
	LastModDate      uint16
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
	NameLen          uint16
	ExtraLen         uint16
	// Name and Extra follow; read separately.
}

const lfhFixedSize = 30

// CentralDirectoryRecord is one entry in the Central Directory.
// ZIP spec section 4.3.12.
type CentralDirectoryRecord struct {
	Signature        uint32 // 0x02014b50
	VersionMadeBy    uint16
	VersionNeeded    uint16
	GPBF             uint16
	Compression      uint16
	LastModTime      uint16
	LastModDate      uint16
	CRC32            uint32
	CompressedSize   uint32
	UncompressedSize uint32
	NameLen          uint16
	ExtraLen         uint16
	CommentLen       uint16
	DiskNumberStart  uint16
	InternalAttrs    uint16
	ExternalAttrs    uint32
	LFHOffset        uint32 // 0xFFFFFFFF means value is in ZIP64 extra field
	// Name, Extra, Comment follow; read separately.
}

const cdrFixedSize = 46

// EndOfCentralDirectory is the EOCD record at the end of the archive.
// ZIP spec section 4.3.16.
type EndOfCentralDirectory struct {
	Signature       uint32 // 0x06054b50
	DiskNumber      uint16
	CDStartDisk     uint16
	CDEntriesOnDisk uint16
	CDEntriesTotal  uint16 // 0xFFFF means value is in ZIP64 EOCD
	CDSize          uint32
	CDOffset        uint32 // 0xFFFFFFFF means value is in ZIP64 EOCD
	CommentLen      uint16
	// Comment follows; read separately.
}

const (
	eocdFixedSize    = 22
	eocdMaxCommentLen = 65535
	eocdSearchSize   = eocdFixedSize + eocdMaxCommentLen
)

// ZIP64EOCDLocator locates the ZIP64 End of Central Directory record.
// It sits immediately before the regular EOCD. ZIP spec section 4.3.15.
type ZIP64EOCDLocator struct {
	Signature    uint32 // 0x07064b50
	StartDisk    uint32
	EOCD64Offset uint64 // file offset of the ZIP64 EOCD record
	TotalDisks   uint32
}

const zip64EOCDLocatorSize = 20

// ZIP64EOCD is the ZIP64 End of Central Directory record.
// It carries 64-bit versions of all fields that overflow in the regular EOCD.
// ZIP spec section 4.3.14.
type ZIP64EOCD struct {
	Signature       uint32 // 0x06064b50
	RecordSize      uint64 // bytes after this field; minimum 44
	VersionMadeBy   uint16
	VersionNeeded   uint16
	DiskNumber      uint32
	CDStartDisk     uint32
	CDEntriesOnDisk uint64
	CDEntriesTotal  uint64
	CDSize          uint64
	CDOffset        uint64
	// Extensible data sector follows if RecordSize > 44; ignored here.
}

// ZIP64ExtraField holds values parsed from a ZIP64 extended information extra
// field (ID 0x0001). Fields are nil when not present in the extra data.
//
// Per the ZIP spec, a field is present only if the corresponding field in the
// main header carries a sentinel value (0xFFFFFFFF for 32-bit, 0xFFFF for
// 16-bit). For LFH context, LFHOffset and DiskStart are never present.
type ZIP64ExtraField struct {
	UncompressedSize *uint64
	CompressedSize   *uint64
	LFHOffset        *uint64 // CD context only
	DiskStart        *uint32 // CD context only
}

// Entry pairs a Central Directory record with its Local File Header.
// It is the primary unit of analysis — discrepancies between the two
// headers surface the malformation techniques used by Android malware.
type Entry struct {
	Name string

	// CD fields
	CD      CentralDirectoryRecord
	CDName  []byte
	CDExtra []byte
	CDZIP64 *ZIP64ExtraField // nil if no ZIP64 extra field in CD

	// LFH fields (populated during Pass 2)
	LFH      LocalFileHeader
	LFHName  []byte
	LFHExtra []byte
	LFHZIP64 *ZIP64ExtraField // nil if no ZIP64 extra field in LFH

	// Resolved offsets (after ZIP64 extra field expansion)
	LFHOffset  int64 // absolute offset of LFH in file
	DataOffset int64 // absolute offset of compressed data

	// Discrepancies detected between CD and LFH
	Issues []Issue
}

// IssueKind classifies a detected malformation.
type IssueKind int

const (
	// Entry-level issues
	IssueEncryptionMismatch     IssueKind = iota // GPBF encryption bit differs
	IssueGPBFMismatch                            // any GPBF bit differs
	IssueCompressionMismatch                     // compression method differs
	IssueUnsupportedCompression                  // not Stored or Deflated
	IssueCRC32Mismatch                           // CRC-32 differs
	IssueCompressedSizeMismatch
	IssueUncompressedSizeMismatch
	IssueNameMismatch          // filename differs between CD and LFH
	IssueDuplicateName         // another entry shares this name (last wins on Android)
	IssueDirectoryFileConflict // a directory entry has same name as a file entry
	IssueLFHSignatureBad       // LFH signature is wrong
	IssueLFHOffsetOutOfRange   // CD-recorded LFH offset is past EOF
	IssueZIP64SentinelMismatch // one header uses 0xFFFFFFFF sentinel, the other does not

	// Archive-level issues (stored in Archive.ArchiveIssues)
	IssueZIP64EOCDMismatch        // ZIP32 and ZIP64 EOCDs disagree on CD offset or entry count
	IssueSigningBlockSizeMismatch // APK Signing Block leading and trailing size fields differ
	IssueSigningBlockUnknownID    // APK Signing Block contains an unrecognised ID-value pair

	// Filename issues (stored in Entry.Issues for every affected entry)
	IssueFilenameControlChar      // C0 control character (0x00-0x1F) or DEL (0x7F) in name
	IssueFilenameInvalidUTF8      // name bytes are not valid UTF-8
	IssueFilenameDangerousUnicode // direction override, zero-width, or BOM codepoint in name
	IssueFilenamePathTraversal    // path traversal or absolute path sequence in name

	// AXML (binary AndroidManifest.xml) issues (stored in the manifest Entry.Issues)
	IssueAXMLBadMagic              // outer chunk type is not 0x0003
	IssueAXMLStringCountMismatch   // string count implies an offset table that overlaps string data
	IssueAXMLStringDuplicateOffset // two strings share the same offset in the offset table
	IssueAXMLChunkMisaligned       // a chunk size is not a multiple of 4
	IssueAXMLAttributeSizeInvalid  // Start Element attributeSize != 0x0014
	IssueAXMLAttributeStartInvalid // Start Element attributeStart != 0x0014
	IssueAXMLOffsetOutOfBounds     // a string offset points outside the string pool data region
)

var issueNames = map[IssueKind]string{
	IssueEncryptionMismatch:     "encryption_mismatch",
	IssueGPBFMismatch:           "gpbf_mismatch",
	IssueCompressionMismatch:    "compression_mismatch",
	IssueUnsupportedCompression: "unsupported_compression",
	IssueCRC32Mismatch:          "crc32_mismatch",
	IssueCompressedSizeMismatch:   "compressed_size_mismatch",
	IssueUncompressedSizeMismatch: "uncompressed_size_mismatch",
	IssueNameMismatch:             "name_mismatch",
	IssueDuplicateName:            "duplicate_name",
	IssueDirectoryFileConflict:    "directory_file_conflict",
	IssueLFHSignatureBad:          "lfh_signature_bad",
	IssueLFHOffsetOutOfRange:      "lfh_offset_out_of_range",
	IssueZIP64SentinelMismatch:    "zip64_sentinel_mismatch",
	IssueZIP64EOCDMismatch:        "zip64_eocd_mismatch",
	IssueSigningBlockSizeMismatch:  "signing_block_size_mismatch",
	IssueSigningBlockUnknownID:     "signing_block_unknown_id",
	IssueAXMLBadMagic:              "axml_bad_magic",
	IssueAXMLStringCountMismatch:   "axml_string_count_mismatch",
	IssueAXMLStringDuplicateOffset: "axml_string_duplicate_offset",
	IssueAXMLChunkMisaligned:       "axml_chunk_misaligned",
	IssueAXMLAttributeSizeInvalid:  "axml_attribute_size_invalid",
	IssueAXMLAttributeStartInvalid: "axml_attribute_start_invalid",
	IssueAXMLOffsetOutOfBounds:     "axml_offset_out_of_bounds",
	IssueFilenameControlChar:       "filename_control_char",
	IssueFilenameInvalidUTF8:       "filename_invalid_utf8",
	IssueFilenameDangerousUnicode:  "filename_dangerous_unicode",
	IssueFilenamePathTraversal:     "filename_path_traversal",
}

func (k IssueKind) String() string {
	if s, ok := issueNames[k]; ok {
		return s
	}
	return "unknown"
}

// Issue records a single detected malformation on an entry or archive.
type Issue struct {
	Kind     IssueKind
	CDValue  any // value from the Central Directory (or ZIP32 EOCD)
	LFHValue any // value from the Local File Header or ZIP64 EOCD
}
