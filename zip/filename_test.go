package zip_test

import (
	"testing"

	"github.com/palmerc/androidzip/zip"
)

// TestFilenameClean: a well-formed ASCII filename produces no filename issues.
func TestFilenameClean(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{name: "assets/icon.png", data: []byte("png")})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, "assets/icon.png")
	if e == nil {
		return
	}
	for _, issue := range e.Issues {
		switch issue.Kind {
		case zip.IssueFilenameControlChar,
			zip.IssueFilenameInvalidUTF8,
			zip.IssueFilenameDangerousUnicode,
			zip.IssueFilenamePathTraversal:
			t.Errorf("unexpected filename issue %v", issue.Kind)
		}
	}
}

// TestFilenameControlChar: a null byte in the filename is a control character.
// C-string APIs treat it as a terminator, hiding the rest of the path.
func TestFilenameControlChar(t *testing.T) {
	name := []byte("classes\x00.dex") // null byte in name
	var ab archiveBuilder
	ab.add(entrySpec{
		name:        "classes\x00.dex",
		data:        []byte("dex"),
		cdNameBytes: name,
	})
	archive := mustOpen(t, ab.build())

	// Entry.Name is set from the raw CD name bytes (Go string includes the null).
	var found *zip.Entry
	for _, e := range archive.Entries {
		found = e
		break
	}
	if found == nil {
		t.Fatal("no entries found")
	}
	assertHasIssue(t, found.Issues, zip.IssueFilenameControlChar)
}

// TestFilenameInvalidUTF8: a filename with an overlong sequence or orphaned
// continuation byte is not valid UTF-8.
func TestFilenameInvalidUTF8(t *testing.T) {
	// 0xFF is not a valid UTF-8 byte in any context.
	name := []byte{'c', 'l', 'a', 's', 's', 'e', 's', 0xFF, '.', 'd', 'e', 'x'}
	var ab archiveBuilder
	ab.add(entrySpec{
		name:        "classes.dex",
		data:        []byte("dex"),
		cdNameBytes: name,
	})
	archive := mustOpen(t, ab.build())

	var found *zip.Entry
	for _, e := range archive.Entries {
		found = e
		break
	}
	if found == nil {
		t.Fatal("no entries found")
	}
	assertHasIssue(t, found.Issues, zip.IssueFilenameInvalidUTF8)
}

// TestFilenameDangerousUnicode: U+202E RIGHT-TO-LEFT OVERRIDE makes the
// displayed filename appear to end in ".jpg" while actually ending in ".exe".
func TestFilenameDangerousUnicode(t *testing.T) {
	// e.g. "photo‮gpj.exe" — rendered RTL as "photo.jpg.exe" → "photo.jpg"
	nameStr := "photo‮gpj.exe"
	var ab archiveBuilder
	ab.add(entrySpec{
		name: nameStr,
		data: []byte("payload"),
	})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, nameStr)
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueFilenameDangerousUnicode)
}

// TestFilenamePathTraversalDotDot: "../" prefix escapes the extraction root.
func TestFilenamePathTraversalDotDot(t *testing.T) {
	name := "../etc/cron.d/backdoor"
	var ab archiveBuilder
	ab.add(entrySpec{name: name, data: []byte("payload")})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, name)
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueFilenamePathTraversal)
}

// TestFilenamePathTraversalAbsolute: an absolute path bypasses the output root.
func TestFilenamePathTraversalAbsolute(t *testing.T) {
	name := "/etc/passwd"
	var ab archiveBuilder
	ab.add(entrySpec{name: name, data: []byte("payload")})
	archive := mustOpen(t, ab.build())

	e := entryNamed(t, archive.Entries, name)
	if e == nil {
		return
	}
	assertHasIssue(t, e.Issues, zip.IssueFilenamePathTraversal)
}
