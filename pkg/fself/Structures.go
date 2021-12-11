package fself

// SelfHeader is the SELF file header structure.
type SelfHeader struct {
	Magic      uint32
	Version    uint8
	Mode       uint8
	Endian     uint8
	Attributes uint8
	KeyType    uint32
	HeaderSize uint16
	MetaSize   uint16
	FileSize   uint64
	NumEntries uint16
	Flags      uint16
}

// SelfEntry is the SELF entry structure, which contains metadata information. There are usually two per segment.
type SelfEntry struct {
	Properties uint64
	Offset     uint64
	FileSize   uint64
	MemorySize uint64
}

// SelfEntryInfo is similar to SelfEntry, however it contains a Data field to keep track of segment data.
type SelfEntryInfo struct {
	Properties uint64
	Offset     uint64
	FileSize   uint64
	MemorySize uint64
	Data       *[]byte
}

// SelfNpdrmControlBlock contains the structure for the NPDRM control blow, which includes the type and content ID
type SelfNpdrmControlBlock struct {
	Type      uint16
	Unknown   [0x0E]byte
	ContentID [0x13]byte
	RandomPad [0x0D]byte
}

// SelfExtendedInfo contains app-specific information about the SELF, including the paid type, app type, app/fw
// version, and the sha256 digest.
type SelfExtendedInfo struct {
	Paid       uint64
	Type       uint64
	AppVersion uint64
	FwVersion  uint64
	Digest     [0x20]byte
}
