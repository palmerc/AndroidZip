package zip

import (
	"strings"
	"unicode/utf8"
)

// dangerousRanges are Unicode codepoint ranges whose presence in a filename
// can deceive analysts: direction overrides (e.g. U+202E RLO), zero-width
// joiners/non-joiners, BOM, and other invisible formatting characters.
// Android does not reject any of these; analysis tools may render misleading
// filenames as a result.
//
// AOSP: no explicit allowlist — Android accepts any UTF-8 sequence that passes
// the basic name checks in libziparchive and PackageParser.
var dangerousRanges = [][2]rune{
	{0x200B, 0x200F}, // zero-width space, ZWNJ, ZWJ, LRM, RLM
	{0x202A, 0x202E}, // LRE, RLE, PDF, LRO, RLO (direction overrides)
	{0x2060, 0x2064}, // word joiner, invisible operators
	{0x206A, 0x206F}, // inhibit symmetric swapping, etc.
	{0xFEFF, 0xFEFF}, // BOM / zero-width no-break space
	{0xFFF9, 0xFFFB}, // interlinear annotation anchors
}

// pathTraversalSequences are byte sequences that let a filename escape its
// intended directory.  Android's installer rejects entries with these patterns;
// many analysis tools extract them literally, creating files outside the output
// directory.
//
// AOSP: platform/frameworks/base: PackageParser.java, isValidApkPath()
var pathTraversalSequences = []string{
	"../", // Unix parent traversal
	".." + string([]byte{0x5c}), // "..\": Windows parent traversal
	"./",  // current-directory prefix (unnecessary but sometimes exploited)
}

// auditFilenames checks every entry's CD name bytes for filename-level issues.
// It operates on the raw CDName bytes so it can detect invalid UTF-8 sequences
// that the Go string conversion would silently replace.
func auditFilenames(entries []*Entry) {
	for _, e := range entries {
		e.Issues = append(e.Issues, auditFilename(e.CDName)...)
	}
}

// auditFilename returns Issues for a single raw filename byte slice.
func auditFilename(name []byte) []Issue {
	var issues []Issue

	// ── 1. Control characters ────────────────────────────────────────────────
	// C0 control chars (0x00–0x1F) and DEL (0x7F) in a filename are invisible
	// in most renderers and can confuse string terminators in C code that
	// processes the name verbatim.
	for _, b := range name {
		if b < 0x20 || b == 0x7F {
			issues = append(issues, Issue{
				Kind:    IssueFilenameControlChar,
				CDValue: b,
			})
			break
		}
	}

	// ── 2. UTF-8 validity ────────────────────────────────────────────────────
	// GPBF bit 11 signals UTF-8; Android calls string(nameBytes) which is
	// tolerant of invalid sequences. Tools that validate UTF-8 strictly will
	// reject or mangle the name.
	if !utf8.Valid(name) {
		issues = append(issues, Issue{
			Kind:    IssueFilenameInvalidUTF8,
			CDValue: name,
		})
	}

	// ── 3. Dangerous Unicode ─────────────────────────────────────────────────
	// Only checked when the bytes are valid UTF-8 to avoid double-reporting.
	if utf8.Valid(name) {
		s := string(name)
		for _, r := range s {
			if isDangerousUnicode(r) {
				issues = append(issues, Issue{
					Kind:    IssueFilenameDangerousUnicode,
					CDValue: s,
				})
				break
			}
		}
	}

	// ── 4. Path traversal ───────────────────────────────────────────────────
	s := string(name)
	if strings.HasPrefix(s, "/") {
		issues = append(issues, Issue{
			Kind:    IssueFilenamePathTraversal,
			CDValue: s,
		})
	} else {
		for _, seq := range pathTraversalSequences {
			if strings.Contains(s, seq) {
				issues = append(issues, Issue{
					Kind:    IssueFilenamePathTraversal,
					CDValue: s,
				})
				break
			}
		}
	}

	return issues
}

func isDangerousUnicode(r rune) bool {
	for _, rng := range dangerousRanges {
		if r >= rng[0] && r <= rng[1] {
			return true
		}
	}
	return false
}
