package zip

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

var apkSigBlockMagic = []byte("APK Sig Block 42")

const (
	sigBlockMagicLen  = 16
	sigBlockSizeLen   = 8  // uint64
	sigBlockFooterLen = sigBlockMagicLen + sigBlockSizeLen // 24: trailing size + magic
	sigBlockMinSize   = sigBlockFooterLen + sigBlockSizeLen // 32: footer + leading size
)

// Known APK Signing Block IDs.
// AOSP: platform/tools/apksig, ApkSigningBlockUtils.java
const (
	SigningBlockIDV2            uint32 = 0x7109871a
	SigningBlockIDV3            uint32 = 0x1b93ad61
	SigningBlockIDV3_1          uint32 = 0x42374f3d
	SigningBlockIDSourceStampV1 uint32 = 0x2146444e
	SigningBlockIDSourceStampV2 uint32 = 0x6dff800d
)

var knownBlockIDs = map[uint32]string{
	SigningBlockIDV2:            "APK Signature Scheme v2",
	SigningBlockIDV3:            "APK Signature Scheme v3",
	SigningBlockIDV3_1:          "APK Signature Scheme v3.1",
	SigningBlockIDSourceStampV1: "Source Stamp v1",
	SigningBlockIDSourceStampV2: "Source Stamp v2",
}

// SigningBlockPair is one ID-value entry within the APK Signing Block.
type SigningBlockPair struct {
	ID    uint32
	Name  string // human-readable name; empty when the ID is unrecognised
	Value []byte
}

// SigningBlock holds the parsed APK Signing Block.
type SigningBlock struct {
	Offset int64  // absolute file offset of the block start (the leading size field)
	Size   uint64 // value of the size fields (bytes after the leading size field)
	Pairs  []SigningBlockPair
}

// FindSigningBlock searches for an APK Signing Block immediately before the
// Central Directory at cdOffset.
//
// The block is identified by the 16-byte magic "APK Sig Block 42" at
// cdOffset-16. If the magic is absent the archive has no signing block and
// nil is returned with no error.
//
// Block layout (all little-endian):
//
//	[8]  leading size  = N (bytes after this field)
//	[N-24] ID-value pairs
//	[8]  trailing size = N  (same value, consistency check)
//	[16] magic "APK Sig Block 42"
//	     ← cdOffset
//
// Each ID-value pair:
//
//	[8]  pair size (bytes after this field, including the 4-byte ID)
//	[4]  block ID
//	[pair_size-4] value
//
// AOSP: platform/tools/apksig, ApkSigningBlockUtils.java, findApkSigningBlock()
func FindSigningBlock(r io.ReadSeeker, cdOffset int64) (*SigningBlock, []Issue, error) {
	if cdOffset < int64(sigBlockMinSize) {
		return nil, nil, nil
	}

	// Check for magic immediately before the Central Directory.
	if _, err := r.Seek(cdOffset-sigBlockMagicLen, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek signing block magic: %w", err)
	}
	magic := make([]byte, sigBlockMagicLen)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, nil, fmt.Errorf("read signing block magic: %w", err)
	}
	if !bytes.Equal(magic, apkSigBlockMagic) {
		return nil, nil, nil // not a signed APK
	}

	// Read the trailing size field (8 bytes before the magic).
	if _, err := r.Seek(cdOffset-int64(sigBlockFooterLen), io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek signing block trailing size: %w", err)
	}
	var trailingSize uint64
	if err := binary.Read(r, order, &trailingSize); err != nil {
		return nil, nil, fmt.Errorf("read signing block trailing size: %w", err)
	}

	// Block start: cdOffset − trailingSize − 8 (the leading size field).
	// trailingSize counts bytes after the leading size field:
	//   pairs + trailing-size-field(8) + magic(16)
	// So the full block is trailingSize+8 bytes, starting at cdOffset−trailingSize−8.
	blockStart := cdOffset - int64(trailingSize) - int64(sigBlockSizeLen)
	if blockStart < 0 {
		return nil, nil, fmt.Errorf("signing block size %d places block start before file beginning", trailingSize)
	}

	// Read the leading size field and compare with the trailing size field.
	if _, err := r.Seek(blockStart, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek signing block start: %w", err)
	}
	var leadingSize uint64
	if err := binary.Read(r, order, &leadingSize); err != nil {
		return nil, nil, fmt.Errorf("read signing block leading size: %w", err)
	}

	var issues []Issue
	if leadingSize != trailingSize {
		issues = append(issues, Issue{
			Kind:     IssueSigningBlockSizeMismatch,
			CDValue:  leadingSize,
			LFHValue: trailingSize,
		})
	}

	// Parse ID-value pairs from just after the leading size field to just
	// before the trailing size field.
	pairsStart := blockStart + int64(sigBlockSizeLen)
	pairsEnd := cdOffset - int64(sigBlockFooterLen)

	pairs, pairIssues, err := parseSigningBlockPairs(r, pairsStart, pairsEnd)
	if err != nil {
		return nil, issues, fmt.Errorf("parse signing block pairs: %w", err)
	}
	issues = append(issues, pairIssues...)

	return &SigningBlock{
		Offset: blockStart,
		Size:   trailingSize,
		Pairs:  pairs,
	}, issues, nil
}

func parseSigningBlockPairs(r io.ReadSeeker, start, end int64) ([]SigningBlockPair, []Issue, error) {
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return nil, nil, err
	}

	var pairs []SigningBlockPair
	var issues []Issue
	pos := start

	for pos < end {
		var pairSize uint64
		if err := binary.Read(r, order, &pairSize); err != nil {
			return pairs, issues, fmt.Errorf("read pair size at %d: %w", pos, err)
		}
		pos += int64(sigBlockSizeLen)

		if pairSize < 4 {
			return pairs, issues, fmt.Errorf("pair size %d at offset %d is too small (minimum 4)", pairSize, pos)
		}
		if pos+int64(pairSize) > end {
			return pairs, issues, fmt.Errorf("pair at offset %d extends past block boundary", pos)
		}

		var id uint32
		if err := binary.Read(r, order, &id); err != nil {
			return pairs, issues, fmt.Errorf("read pair ID: %w", err)
		}
		pos += 4

		valueLen := int(pairSize) - 4
		value := make([]byte, valueLen)
		if _, err := io.ReadFull(r, value); err != nil {
			return pairs, issues, fmt.Errorf("read pair value: %w", err)
		}
		pos += int64(valueLen)

		name := knownBlockIDs[id]
		if name == "" {
			issues = append(issues, Issue{
				Kind:    IssueSigningBlockUnknownID,
				CDValue: fmt.Sprintf("0x%08x", id),
			})
		}

		pairs = append(pairs, SigningBlockPair{ID: id, Name: name, Value: value})
	}

	return pairs, issues, nil
}
