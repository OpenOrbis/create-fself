package oelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
)

// RewriteELFHeader will overwrite the existing ELF header to be compatible with the PS4's expectations. This includes
// an adjusted program header count, an ET_SCE_EXEC_ASLR type, and an updated identifier. Returns an error if the write
// failed, nil otherwise.
func (orbisElf *OrbisElf) RewriteELFHeader() error {
	var (
		inputFile *os.File
		err       error
	)

	elfHeaderBuff := new(bytes.Buffer)
	programHeaderCount := uint16(len(orbisElf.ProgramHeaders))

	elfType := ET_SCE_EXEC_ASLR
	elfEntry := orbisElf.ElfToConvert.Entry

	if orbisElf.IsLibrary {
		elfType = ET_SCE_DYNAMIC
		elfEntry = 0
	}

	// Get the section header offset info from the original file
	inputHdr := new(elf.Header64)

	if inputFile, err = os.Open(orbisElf.ElfToConvertName); err != nil {
		return err
	}

	if _, err = inputFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err = binary.Read(inputFile, orbisElf.ElfToConvert.ByteOrder, inputHdr); err != nil {
		return err
	}

	// Create the header
	header := elf.Header64{
		Ident: [0x10]byte{
			0x7F, 0x45, 0x4C, 0x46,
			0x02,
			0x01,
			0x01,
			0x09,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},

		Version:   1,
		Type:      uint16(elfType),
		Machine:   uint16(elf.EM_X86_64),
		Entry:     elfEntry,
		Ehsize:    0x40,
		Phoff:     0x40,
		Phentsize: 0x38,
		Phnum:     programHeaderCount,
		Shoff:     inputHdr.Shoff,
		Shentsize: inputHdr.Shentsize,
		Shnum:     inputHdr.Shnum,
		Shstrndx:  inputHdr.Shstrndx,
		Flags:     0,
	}

	if err := binary.Write(elfHeaderBuff, binary.LittleEndian, header); err != nil {
		return err
	}

	if _, err := orbisElf.FinalFile.WriteAt(elfHeaderBuff.Bytes(), 0); err != nil {
		return err
	}

	return nil
}

// RewriteSDKVersion will overwrite the SDK version magic in .data.sce_process_param with the given argument.
// Returns an error if the write failed, nil otherwise.
func (orbisElf *OrbisElf) RewriteSDKVersion(sdkVer int) error {
	sdkVersion := intToByteArray(sdkVer)
	sectionName := ".data.sce_process_param"

	if orbisElf.IsLibrary {
		sectionName = ".data.sce_module_param"
	}

	// Get the offset of .sce_process_param
	rewriteOffset, err := orbisElf.getFileOffsetBySectionName(sectionName)

	if err != nil {
		return err
	}

	// SDK version will be +0x10 in .sce_process_param/.sce_module_param
	rewriteOffset += 0x10

	// Commit the write
	_, err = orbisElf.FinalFile.WriteAt(sdkVersion, rewriteOffset)
	return err
}

// RewriteInterpreter will overwrite the first 0x20 bytes of .text with the given interpreter string. Returns
// an error if the write failed, nil otherwise.
func (orbisElf *OrbisElf) RewriteInterpreter(interpreter string) error {
	interpreterBuff := make([]byte, 0x20)
	copy(interpreterBuff[:], interpreter)

	// Get the offset of .text - the interpreter is at 0x00 of .text
	rewriteOffset, err := orbisElf.getFileOffsetBySectionName(".text")

	if err != nil {
		return err
	}

	// Commit the write
	_, err = orbisElf.FinalFile.WriteAt(interpreterBuff, rewriteOffset)
	return err
}

// RewriteDynamicSectionHeader will overwrite the address of the .dynamic section with the given address. Returns
// an error if the write failed, nil otherwise.
func (orbisElf *OrbisElf) RewriteDynamicSectionHeader() error {
	var (
		inputFile *os.File
		err       error
	)

	// Get the section header offset info from the original file
	inputHdr := new(elf.Header64)

	if inputFile, err = os.Open(orbisElf.ElfToConvertName); err != nil {
		return err
	}

	if _, err = inputFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err = binary.Read(inputFile, orbisElf.ElfToConvert.ByteOrder, inputHdr); err != nil {
		return err
	}

	sectionHeadersOffset := inputHdr.Shoff

	// Find the dynamic header
	for i := uint16(0); i < inputHdr.Shnum; i++ {
		sectionHdr := new(elf.Section64)
		sectionHeaderOffset := int64(sectionHeadersOffset + uint64(i*inputHdr.Shentsize))

		if _, err = inputFile.Seek(sectionHeaderOffset, io.SeekStart); err != nil {
			return err
		}

		if err = binary.Read(inputFile, orbisElf.ElfToConvert.ByteOrder, sectionHdr); err != nil {
			return err
		}

		if sectionHdr.Type == uint32(elf.SHT_DYNAMIC) {
			sectionHeaderBuff := new(bytes.Buffer)

			// Rewrite the address
			sectionHdr.Off = _offsetOfDynamic
			sectionHdr.Addr = _offsetOfDynamic
			sectionHdr.Size = _sizeOfDynamic

			// Commit the write
			if err := binary.Write(sectionHeaderBuff, binary.LittleEndian, sectionHdr); err != nil {
				return err
			}

			if _, err := orbisElf.FinalFile.WriteAt(sectionHeaderBuff.Bytes(), sectionHeaderOffset); err != nil {
				return err
			}

			break
		}
	}

	return nil
}
