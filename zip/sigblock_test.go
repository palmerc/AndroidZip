package zip_test

import (
	"bytes"
	"testing"

	"github.com/palmerc/androidzip/zip"
)

// buildSigningBlockBytes constructs the raw bytes of an APK Signing Block.
//
// Layout written:
//
//	[8]  leading size  (overridable for mismatch tests; trailing is always N)
//	[N-24] ID-value pairs
//	[8]  trailing size = N
//	[16] magic
//
// Overriding the leading size (not the trailing) keeps the block location
// calculable from the trailing size, so the parser reaches the right offset
// and detects the mismatch without cascading into a parse error.
func buildSigningBlockBytes(pairs []sigPair, leadingSizeOverride *uint64) []byte {
	var pairsBuf bytes.Buffer
	for _, p := range pairs {
		pairSize := uint64(4 + len(p.value))
		pairsBuf.Write(le64(pairSize))
		pairsBuf.Write(le32(p.id))
		pairsBuf.Write(p.value)
	}

	// N = pairs + trailing size field + magic
	n := uint64(pairsBuf.Len()) + 8 + 16

	leading := n
	if leadingSizeOverride != nil {
		leading = *leadingSizeOverride
	}

	var buf bytes.Buffer
	buf.Write(le64(leading)) // leading size (may differ from N for mismatch tests)
	buf.Write(pairsBuf.Bytes())
	buf.Write(le64(n))  // trailing size always = N (used to locate the block)
	buf.Write([]byte("APK Sig Block 42"))
	return buf.Bytes()
}

type sigPair struct {
	id    uint32
	value []byte
}

// buildSignedAPK assembles a minimal one-entry APK with an APK Signing Block.
func buildSignedAPK(pairs []sigPair, leadingSizeOverride *uint64) []byte {
	data := []byte("dex\n035")
	name := []byte("classes.dex")

	var buf bytes.Buffer

	// LFH
	lfhOffset := uint32(buf.Len())
	buf.Write(le32(0x04034b50))
	buf.Write(le16(20))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le32(checksum(data)))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le16(uint16(len(name))))
	buf.Write(le16(0))
	buf.Write(name)
	buf.Write(data)

	// APK Signing Block
	buf.Write(buildSigningBlockBytes(pairs, leadingSizeOverride))

	// Central Directory
	cdOffset := uint32(buf.Len())
	buf.Write(le32(0x02014b50))
	buf.Write(le16(20))
	buf.Write(le16(20))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le32(checksum(data)))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le32(uint32(len(data))))
	buf.Write(le16(uint16(len(name))))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le32(0))
	buf.Write(le32(lfhOffset))
	buf.Write(name)

	cdSize := uint32(buf.Len()) - cdOffset

	// EOCD
	buf.Write(le32(0x06054b50))
	buf.Write(le16(0))
	buf.Write(le16(0))
	buf.Write(le16(1))
	buf.Write(le16(1))
	buf.Write(le32(cdSize))
	buf.Write(le32(cdOffset))
	buf.Write(le16(0))

	return buf.Bytes()
}

// TestSigningBlockAbsent confirms that a regular ZIP without a signing block
// produces a nil SigningBlock and no related issues.
func TestSigningBlockAbsent(t *testing.T) {
	var ab archiveBuilder
	ab.add(entrySpec{name: "classes.dex", data: []byte("dex\n035")})
	archive := mustOpen(t, ab.build())

	if archive.SigningBlock != nil {
		t.Errorf("expected no signing block, got one at offset %d", archive.SigningBlock.Offset)
	}
	for _, issue := range archive.ArchiveIssues {
		if issue.Kind == zip.IssueSigningBlockSizeMismatch ||
			issue.Kind == zip.IssueSigningBlockUnknownID {
			t.Errorf("unexpected signing block issue: %v", issue.Kind)
		}
	}
}

// TestSigningBlockV2 confirms that a v2 signing block is detected and the
// correct scheme name is reported.
func TestSigningBlockV2(t *testing.T) {
	apk := buildSignedAPK([]sigPair{
		{id: zip.SigningBlockIDV2, value: []byte("fake v2 sig data")},
	}, nil)
	archive := mustOpen(t, apk)

	if archive.SigningBlock == nil {
		t.Fatal("expected signing block, got nil")
	}
	if len(archive.SigningBlock.Pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(archive.SigningBlock.Pairs))
	}
	if archive.SigningBlock.Pairs[0].Name != "APK Signature Scheme v2" {
		t.Errorf("unexpected pair name %q", archive.SigningBlock.Pairs[0].Name)
	}
	assertNoIssues(t, archive.ArchiveIssues)
}

// TestSigningBlockV2V3 confirms that both v2 and v3 scheme pairs are parsed
// when co-present, as is common in modern APKs targeting API 28+.
func TestSigningBlockV2V3(t *testing.T) {
	apk := buildSignedAPK([]sigPair{
		{id: zip.SigningBlockIDV2, value: []byte("fake v2 sig data")},
		{id: zip.SigningBlockIDV3, value: []byte("fake v3 sig data")},
	}, nil)
	archive := mustOpen(t, apk)

	if archive.SigningBlock == nil {
		t.Fatal("expected signing block, got nil")
	}
	if len(archive.SigningBlock.Pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(archive.SigningBlock.Pairs))
	}
	assertNoIssues(t, archive.ArchiveIssues)
}

// TestSigningBlockSizeMismatch: the leading size field differs from the
// trailing size field. Android's apksig rejects the block; tools checking only
// one size field accept it.
//
// We override the leading size (not the trailing) so the block is still
// located correctly by the trailing size, and the mismatch is detected
// without triggering a cascade parse error.
func TestSigningBlockSizeMismatch(t *testing.T) {
	wrongLeading := uint64(999)
	apk := buildSignedAPK([]sigPair{
		{id: zip.SigningBlockIDV2, value: []byte("fake v2 sig data")},
	}, &wrongLeading)
	archive := mustOpen(t, apk)

	assertHasIssue(t, archive.ArchiveIssues, zip.IssueSigningBlockSizeMismatch)
}

// TestSigningBlockUnknownID: a block ID that is not in the known-ID registry.
// Android ignores it; some analysis tools may reject or misparse the block.
func TestSigningBlockUnknownID(t *testing.T) {
	apk := buildSignedAPK([]sigPair{
		{id: zip.SigningBlockIDV2, value: []byte("fake v2 sig data")},
		{id: 0xDEADBEEF, value: []byte("mystery block")},
	}, nil)
	archive := mustOpen(t, apk)

	assertHasIssue(t, archive.ArchiveIssues, zip.IssueSigningBlockUnknownID)
}
