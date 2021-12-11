package fself

// writeNullBytes takes a given size and writes null bytes to the buffer. Returns the number of null bytes written.
func writeNullBytes(buffer *[]byte, size uint64) uint64 {
	nullBytes := make([]byte, size)

	for i := uint64(0); i < size; i++ {
		nullBytes[i] = 0
	}

	*buffer = append(*buffer, nullBytes...)
	return size
}

// writePaddingBytes takes a given size and alignment, and uses that to write null padding to buffer. Returns the number of
// null bytes written.
func writePaddingBytes(buffer *[]byte, size uint64, align uint64) uint64 {
	padding := -size & (align - 1)
	return writeNullBytes(buffer, padding)
}
