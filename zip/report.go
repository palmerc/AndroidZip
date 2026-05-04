package zip

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Severity classifies how impactful a malformation is for analysis.
type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// issueDetail holds static metadata about a malformation kind.
type issueDetail struct {
	Severity    Severity
	Description string // what the malformation does
	AndroidBehavior string // how Android handles it vs. analysis tools
	AOSPSource  string // canonical source reference
}

// issueRegistry maps each IssueKind to its explanatory metadata.
// AOSP paths reference the Android Open Source Project at
// https://cs.android.com — browse by path under platform/.
var issueRegistry = map[IssueKind]issueDetail{
	IssueEncryptionMismatch: {
		Severity: SeverityCritical,
		Description: "The encryption flag (GPBF bit 0) differs between the Central Directory " +
			"and Local File Header. The data is not actually encrypted.",
		AndroidBehavior: "libziparchive populates ZipEntry.gpbf from the Central Directory. " +
			"The device installs the file without decryption. Analysis tools that trust " +
			"the opposing header stall, prompt for a password, or refuse to extract.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal() / FindEntry()",
	},
	IssueGPBFMismatch: {
		Severity: SeverityHigh,
		Description: "The General Purpose Bit Flag differs between the Central Directory and " +
			"Local File Header. One or more flag bits is a decoy.",
		AndroidBehavior: "libziparchive uses GPBF from the Central Directory for all flag checks " +
			"(encryption, data descriptor, UTF-8 name). The LFH GPBF is only checked " +
			"as a secondary consistency test in some Android versions.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal()",
	},
	IssueCompressionMismatch: {
		Severity: SeverityHigh,
		Description: "The compression method field differs between the Central Directory and " +
			"Local File Header.",
		AndroidBehavior: "libziparchive reads the compression method from the Central Directory " +
			"to select a decompressor. The LFH compression field is not used for " +
			"decompression decisions. Tools that read the LFH first will attempt to " +
			"decompress with the wrong algorithm.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, ExtractToWriter()",
	},
	IssueUnsupportedCompression: {
		Severity: SeverityCritical,
		Description: "The compression method is not STORED (0x0000) or DEFLATED (0x0008). " +
			"Android only natively supports these two methods during APK installation.",
		AndroidBehavior: "PackageManager / libziparchive treats any unrecognised compression " +
			"method as STORED, reading the bytes verbatim. Analysis tools that enforce " +
			"the ZIP specification will reject the entry or throw an exception.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, ExtractToWriter(); " +
			"platform/frameworks/base: PackageManagerService.java",
	},
	IssueCRC32Mismatch: {
		Severity: SeverityMedium,
		Description: "The CRC-32 checksum differs between the Central Directory and Local File Header.",
		AndroidBehavior: "Android uses the CD CRC-32 for integrity checking. A mismatched LFH " +
			"CRC-32 is not flagged during installation. Strict tools perform CRC validation " +
			"against the LFH value and may reject the archive.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, ValidateDataDescriptor()",
	},
	IssueCompressedSizeMismatch: {
		Severity: SeverityMedium,
		Description: "The compressed file size differs between the Central Directory and Local File Header.",
		AndroidBehavior: "libziparchive uses the CD size to bound read operations. An inflated " +
			"LFH size causes some tools to read past the file boundary into adjacent entries.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal()",
	},
	IssueUncompressedSizeMismatch: {
		Severity: SeverityMedium,
		Description: "The uncompressed file size differs between the Central Directory and Local File Header.",
		AndroidBehavior: "libziparchive allocates output buffers based on the CD uncompressed size. " +
			"A falsified LFH size can cause allocation failures or truncation in analysis tools.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, ExtractToWriter()",
	},
	IssueNameMismatch: {
		Severity: SeverityHigh,
		Description: "The entry filename differs between the Central Directory and Local File Header.",
		AndroidBehavior: "Android resolves entry names from the Central Directory. A tool that " +
			"scans Local File Headers sequentially will see a different filename, " +
			"potentially indexing a decoy entry under the wrong name.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal()",
	},
	IssueDuplicateName: {
		Severity: SeverityCritical,
		Description: "Two or more Central Directory entries share the same filename.",
		AndroidBehavior: "libziparchive's hash table stores the last entry for any given name. " +
			"Android loads the final duplicate. Tools that use the first entry (e.g. unzip) " +
			"will analyse a decoy payload while Android runs the real one.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal() — " +
			"entries are inserted into a hash map; collisions overwrite the prior entry",
	},
	IssueDirectoryFileConflict: {
		Severity: SeverityCritical,
		Description: "A directory entry (trailing '/') shares a base name with a file entry " +
			"(e.g. 'classes.dex/' and 'classes.dex'). Commonly targets AndroidManifest.xml, " +
			"classes.dex, and resources.arsc.",
		AndroidBehavior: "Android's installer locates entries by name via the Central Directory " +
			"hash table. The directory entry does not shadow the file entry at the OS level. " +
			"Many analysis tools (JADX, apktool) iterate entries and may attempt to create " +
			"a directory at the file's path, causing extraction to fail.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal(); " +
			"platform/frameworks/base: PackageParser.java",
	},
	IssueLFHSignatureBad: {
		Severity: SeverityHigh,
		Description: "The Local File Header at the CD-recorded offset does not carry the " +
			"expected signature (0x04034b50).",
		AndroidBehavior: "libziparchive validates the LFH signature before reading data. A bad " +
			"signature causes extraction failure on Android too, but the entry remains in " +
			"the Central Directory index and may still influence package parsing.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, FindEntry()",
	},
	IssueLFHOffsetOutOfRange: {
		Severity: SeverityCritical,
		Description: "The LFH offset recorded in the Central Directory points beyond the end of the file.",
		AndroidBehavior: "Android will fail to open this entry. However the CD record still " +
			"exists and can confuse tools that trust CD metadata without validating offsets.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal()",
	},
	IssueZIP64SentinelMismatch: {
		Severity: SeverityCritical,
		Description: "One header uses the ZIP64 sentinel value (0xFFFFFFFF) for a size field, " +
			"indicating the real value is in the ZIP64 extra field, while the other header " +
			"carries an actual value in the 32-bit field.",
		AndroidBehavior: "libziparchive reads sizes exclusively from the Central Directory and its " +
			"ZIP64 extra field. An LFH that uses the sentinel without a ZIP64 extra field, " +
			"or vice versa, will cause tools that read the LFH first to see a wildly different " +
			"size — either 4 GiB (0xFFFFFFFF interpreted literally) or an incorrect small value. " +
			"This can cause buffer over-allocation or premature truncation in analysis tools.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal(); " +
			"ZIP Application Note section 4.5.3 (ZIP64 Extended Information Extra Field)",
	},
	IssueSigningBlockSizeMismatch: {
		Severity: SeverityHigh,
		Description: "The APK Signing Block's leading and trailing size fields carry " +
			"different values. Both fields must be identical per the specification.",
		AndroidBehavior: "Android's apksig library validates both size fields and rejects " +
			"the signing block if they disagree, causing signature verification failure. " +
			"Tools that only check one field may silently accept a malformed block, " +
			"producing inconsistent verification results.",
		AOSPSource: "platform/tools/apksig: ApkSigningBlockUtils.java, findApkSigningBlock()",
	},
	IssueSigningBlockUnknownID: {
		Severity: SeverityLow,
		Description: "The APK Signing Block contains an ID-value pair with an unrecognised " +
			"block ID. Known IDs are v2 (0x7109871a), v3 (0x1b93ad61), " +
			"v3.1 (0x42374f3d), Source Stamp v1 (0x2146444e), Source Stamp v2 (0x6dff800d).",
		AndroidBehavior: "Android ignores unrecognised block IDs; the signing block format " +
			"is designed to be extensible. An unknown ID is not itself malicious but may " +
			"indicate a custom or experimental signing scheme.",
		AOSPSource: "platform/tools/apksig: ApkSigningBlockUtils.java, getSupportedSignatureAlgorithms()",
	},
	IssueAXMLBadMagic: {
		Severity: SeverityCritical,
		Description: "The outer chunk type in AndroidManifest.xml is not 0x0003. " +
			"The first two bytes of a valid AXML file must be 0x03 0x00.",
		AndroidBehavior: "Android's ResXMLTree does not strictly validate the outer " +
			"chunk type in all code paths and may continue parsing. Analysis tools " +
			"(JADX, apktool) perform strict magic validation and abort immediately.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResXMLTree::setTo()",
	},
	IssueAXMLStringCountMismatch: {
		Severity: SeverityCritical,
		Description: "The String Pool declares more strings than its stringsStart offset " +
			"can accommodate. The offset table for the declared count would overlap " +
			"or extend past the string data region.",
		AndroidBehavior: "Android's ResStringPool reads the declared count and allocates " +
			"an offset array of that size, then reads stringsStart bytes for each " +
			"offset. An inflated count causes the parser to read string data as if " +
			"it were offsets, producing garbage string references. Analysis tools " +
			"performing bounds checks reject the manifest entirely.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResStringPool::setTo()",
	},
	IssueAXMLStringDuplicateOffset: {
		Severity: SeverityHigh,
		Description: "Two or more entries in the String Pool offset table point to the " +
			"same position in the string data.",
		AndroidBehavior: "Android resolves the string at the given offset normally; " +
			"duplicate entries are silently accepted. Deduplication logic in analysis " +
			"tools may collapse the two references or fail when rebuilding the string " +
			"pool, causing manifest decompilation to produce incorrect output.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResStringPool::stringAt()",
	},
	IssueAXMLChunkMisaligned: {
		Severity: SeverityHigh,
		Description: "A chunk size is not a multiple of 4. All AXML chunks must be " +
			"4-byte aligned; misalignment shifts the position of every subsequent chunk.",
		AndroidBehavior: "Android's chunk walker adds chunkSize to the current position " +
			"without enforcing alignment, so subsequent chunks are found at the wrong " +
			"offsets. Analysis tools that enforce the 4-byte alignment requirement " +
			"fail to locate any chunk after the misaligned one.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResXMLTree::nextNode()",
	},
	IssueAXMLAttributeSizeInvalid: {
		Severity: SeverityCritical,
		Description: "A Start Element chunk's attributeSize field is not 0x0014 (20). " +
			"This field controls how many bytes each attribute occupies; the standard " +
			"ResXMLTree_attribute struct is exactly 20 bytes.",
		AndroidBehavior: "Android's ResXMLParser uses attributeSize to advance through " +
			"the attribute list. A non-standard value shifts every attribute read by " +
			"the difference, producing garbled attribute data. Many analysis tools " +
			"hard-code 20 and crash or produce errors on any other value.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResXMLTree::nextNode(); ResourceTypes.h, ResXMLTree_attrExt",
	},
	IssueAXMLAttributeStartInvalid: {
		Severity: SeverityHigh,
		Description: "A Start Element chunk's attributeStart field is not 0x0014 (20). " +
			"This field is the byte offset from the beginning of ResXMLTree_attrExt " +
			"to the first attribute; the struct itself is 20 bytes.",
		AndroidBehavior: "Android uses attributeStart to locate the first attribute " +
			"relative to the attrExt struct. An unexpected value causes Android to " +
			"read attributes from the wrong position. Analysis tools that assume " +
			"the standard offset fail to parse any attributes in the element.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResXMLTree::nextNode(); ResourceTypes.h, ResXMLTree_attrExt",
	},
	IssueAXMLOffsetOutOfBounds: {
		Severity: SeverityHigh,
		Description: "A string offset in the String Pool offset table points outside " +
			"the string data region of the pool.",
		AndroidBehavior: "Android checks bounds before reading a string. An out-of-bounds " +
			"offset causes Android to return an empty string for that index rather than " +
			"crashing. Tools that do not bounds-check may read arbitrary memory or crash.",
		AOSPSource: "platform/frameworks/base/libs/androidfw/ResourceTypes.cpp, " +
			"ResStringPool::stringAt()",
	},
	IssueFilenameControlChar: {
		Severity: SeverityHigh,
		Description: "The entry filename contains a C0 control character (0x00–0x1F) or DEL (0x7F). " +
			"These bytes are invisible in most renderers and can terminate C strings prematurely.",
		AndroidBehavior: "Android's libziparchive does not validate filenames for control characters; " +
			"the name is used verbatim. Analysis tools and terminal output that interpret control " +
			"bytes may display a truncated or garbled filename, hiding the real path.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal() — " +
			"no control-character filtering is applied to entry names",
	},
	IssueFilenameInvalidUTF8: {
		Severity: SeverityHigh,
		Description: "The entry filename bytes are not valid UTF-8. GPBF bit 11 signals that " +
			"the name is UTF-8 encoded; invalid sequences violate this contract.",
		AndroidBehavior: "Android converts the raw bytes to a Java String using modified UTF-8, " +
			"substituting the replacement character for invalid sequences. Analysis tools that " +
			"validate UTF-8 strictly may reject the entry or produce garbled output, showing a " +
			"different filename than Android resolves.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc; " +
			"platform/libcore: ZipFile.java — Java modified-UTF-8 conversion",
	},
	IssueFilenameDangerousUnicode: {
		Severity: SeverityMedium,
		Description: "The entry filename contains a direction override (e.g. U+202E RLO), " +
			"zero-width character, or BOM codepoint. These codepoints alter visual rendering " +
			"without changing the stored bytes.",
		AndroidBehavior: "Android installs and loads the entry under the bytes as stored, unaffected " +
			"by invisible Unicode. A filename rendered as 'photo.jpg' by a terminal or IDE may " +
			"actually be stored as 'photo‮gpj.exe', hiding a malicious extension from analysts.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc — no Unicode normalisation; " +
			"platform/frameworks/base: PackageParser.java",
	},
	IssueFilenamePathTraversal: {
		Severity: SeverityCritical,
		Description: "The entry filename begins with '/' (absolute path) or contains '../' or '..\\' " +
			"(parent-directory traversal). Extracting this entry can write files outside the " +
			"intended output directory.",
		AndroidBehavior: "Android's PackageManager rejects APKs containing absolute paths or " +
			"traversal sequences via isValidApkPath(). However, analysis tools that extract " +
			"entries without this validation may write files anywhere on disk, enabling " +
			"path-traversal attacks against the analyst's machine.",
		AOSPSource: "platform/frameworks/base: PackageParser.java, isValidApkPath(); " +
			"platform/system/libziparchive: zip_archive.cc",
	},
	IssueZIP64EOCDMismatch: {
		Severity: SeverityCritical,
		Description: "The ZIP32 End of Central Directory and the ZIP64 End of Central Directory " +
			"disagree on the Central Directory offset or total entry count.",
		AndroidBehavior: "When a ZIP64 EOCD is present, libziparchive uses its values and ignores " +
			"the corresponding ZIP32 EOCD fields. Tools that do not implement ZIP64 use the " +
			"ZIP32 EOCD and navigate to a different Central Directory — a decoy CD that " +
			"exposes a benign-looking entry table while Android loads the real one.",
		AOSPSource: "platform/system/libziparchive: zip_archive.cc, OpenArchiveInternal() — " +
			"ZIP64 EOCD locator is checked before falling back to the ZIP32 EOCD",
	},
}

// Report is the full analysis result for one archive, suitable for both
// human-readable and JSON output.
type Report struct {
	Filename      string        `json:"filename"`
	EntryCount    int           `json:"entry_count"`
	IssueCount    int           `json:"issue_count"`
	Signatures    []string      `json:"signatures,omitempty"` // e.g. ["APK Signature Scheme v2"]
	ArchiveIssues []IssueReport `json:"archive_issues,omitempty"`
	Entries       []EntryReport `json:"entries,omitempty"`
}

// EntryReport is the per-entry section of the report.
type EntryReport struct {
	Name   string        `json:"name"`
	Issues []IssueReport `json:"issues"`
}

// IssueReport is the per-issue section of the report.
type IssueReport struct {
	Kind            string `json:"kind"`
	Severity        string `json:"severity"`
	Description     string `json:"description"`
	AndroidBehavior string `json:"android_behavior"`
	AOSPSource      string `json:"aosp_source"`
	CDValue         any    `json:"cd_value,omitempty"`
	LFHValue        any    `json:"lfh_value,omitempty"`
}

// BuildReport assembles a Report from a parsed Archive.
func BuildReport(filename string, archive *Archive) Report {
	r := Report{
		Filename:   filename,
		EntryCount: len(archive.Entries),
	}

	toIssueReport := func(issue Issue) IssueReport {
		detail := issueRegistry[issue.Kind]
		return IssueReport{
			Kind:            issue.Kind.String(),
			Severity:        detail.Severity.String(),
			Description:     detail.Description,
			AndroidBehavior: detail.AndroidBehavior,
			AOSPSource:      detail.AOSPSource,
			CDValue:         issue.CDValue,
			LFHValue:        issue.LFHValue,
		}
	}

	if archive.SigningBlock != nil {
		for _, pair := range archive.SigningBlock.Pairs {
			if pair.Name != "" {
				r.Signatures = append(r.Signatures, pair.Name)
			}
		}
	}

	for _, issue := range archive.ArchiveIssues {
		r.ArchiveIssues = append(r.ArchiveIssues, toIssueReport(issue))
		r.IssueCount++
	}

	for _, e := range archive.Entries {
		if len(e.Issues) == 0 {
			continue
		}
		er := EntryReport{Name: e.Name}
		for _, issue := range e.Issues {
			er.Issues = append(er.Issues, toIssueReport(issue))
			r.IssueCount++
		}
		r.Entries = append(r.Entries, er)
	}

	return r
}

// WriteText writes a human-readable report to w.
func WriteText(w io.Writer, r Report) {
	sep := strings.Repeat("─", 72)

	fmt.Fprintf(w, "\nAndroidZip Malformation Report\n%s\n", sep)
	fmt.Fprintf(w, "File:    %s\n", r.Filename)
	fmt.Fprintf(w, "Entries: %d\n", r.EntryCount)
	if len(r.Signatures) > 0 {
		fmt.Fprintf(w, "Signatures: %s\n", strings.Join(r.Signatures, ", "))
	}
	fmt.Fprintf(w, "Issues:  %d\n", r.IssueCount)

	if r.IssueCount == 0 {
		fmt.Fprintf(w, "\nNo malformations detected.\n")
		return
	}

	if len(r.ArchiveIssues) > 0 {
		fmt.Fprintf(w, "\n%s\n[ARCHIVE STRUCTURE]\n", sep)
		for _, issue := range r.ArchiveIssues {
			writeIssue(w, issue)
		}
	}

	for _, e := range r.Entries {
		fmt.Fprintf(w, "\n%s\n[%s]\n", sep, e.Name)
		for _, issue := range e.Issues {
			writeIssue(w, issue)
		}
	}
	fmt.Fprintf(w, "\n%s\n", sep)
}

func writeIssue(w io.Writer, issue IssueReport) {
	fmt.Fprintf(w, "\n  %s  %s\n", issue.Severity, issue.Kind)
	fmt.Fprintf(w, "  Description:\n    %s\n",
		wordWrap(issue.Description, 68, "    "))
	fmt.Fprintf(w, "  Android behavior:\n    %s\n",
		wordWrap(issue.AndroidBehavior, 68, "    "))
	fmt.Fprintf(w, "  AOSP source:\n    %s\n",
		wordWrap(issue.AOSPSource, 68, "    "))
	if issue.CDValue != nil || issue.LFHValue != nil {
		fmt.Fprintf(w, "  Values:  cd=%-20v  lfh=%v\n",
			issue.CDValue, issue.LFHValue)
	}
}

// WriteJSON writes the report as indented JSON to w.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func wordWrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
		} else {
			line += " " + w
		}
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n"+indent)
}
