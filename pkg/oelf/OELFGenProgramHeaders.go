package oelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"sort"
)

type programHeaderList []*elf.Prog

// GenerateProgramHeaders parses the input ELF's section header table to generate updated program headers.
// Returns nil.
func (orbisElf *OrbisElf) GenerateProgramHeaders() error {
	// Get all the necessary sections first
	// TODO: Verify these sections exist in OrbisElf.ValidateInputELF()
	textSection := orbisElf.ElfToConvert.Section(".text")
	relroSection := orbisElf.ElfToConvert.Section(".data.rel.ro")
	dataSection := orbisElf.ElfToConvert.Section(".data")
	bssSection := orbisElf.ElfToConvert.Section(".bss")
	procParamSection := orbisElf.ElfToConvert.Section(".data.sce_process_param")

	if orbisElf.IsLibrary {
		procParamSection = orbisElf.ElfToConvert.Section(".data.sce_module_param")
	}

	// Get GNU_RELRO header pre-emptively (we'll need to check it to eliminate duplicate PT_LOAD headers)
	gnuRelroSegment := orbisElf.getProgramHeader(elf.PT_GNU_RELRO, elf.PF_R)
	relroAlignedMemsz := align(gnuRelroSegment.Memsz, 0x4000);

	// First pass: drop program headers that we don't need and copy all others
	for _, progHeader := range orbisElf.ElfToConvert.Progs {
		// PT_LOAD read-only should be consolidated into PT_LOAD for .text
		if progHeader.Type == elf.PT_LOAD && progHeader.Flags == elf.PF_R {
			continue
		}

		// PT_LOAD for relro will be handled by SCE_RELRO, we can get rid of it
		if gnuRelroSegment != nil {
			if progHeader.Type == elf.PT_LOAD && progHeader.Off == gnuRelroSegment.Off {
				if progHeader.Memsz > relroAlignedMemsz {
					subtractSize := relroAlignedMemsz
					progHeader.Off += subtractSize
					progHeader.Vaddr += subtractSize
					progHeader.Paddr = 0
					if progHeader.Filesz < subtractSize {
						progHeader.Filesz = 0
					} else {
						progHeader.Filesz -= subtractSize
					}
					progHeader.Memsz -= subtractSize
				} else {
					continue
				}
			}
		}

		// GNU_RELRO will sometimes get generated even if no .data.rel.ro is present. This is bad for PS4 because the
		// header will be unaligned and it's not necessary. Get rid of it if there's no relro section.
		if progHeader.Type == elf.PT_GNU_RELRO && relroSection == nil {
			continue
		}

		// GNU_STACK can be dropped, PS4 doesn't need it
		if progHeader.Type == elf.PT_GNU_STACK {
			continue
		}

		// Keep all others
		orbisElf.ProgramHeaders = append(orbisElf.ProgramHeaders, progHeader)
	}

	// Second pass: modify headers as required
	for _, progHeader := range orbisElf.ProgramHeaders {
		// We generate a new dynamic table, so we'll need to update this header
		if progHeader.Type == elf.PT_DYNAMIC {
			progHeader.Off = _offsetOfDynamic
			progHeader.Vaddr = _offsetOfDynamic
			progHeader.Paddr = _offsetOfDynamic
			progHeader.Filesz = _sizeOfDynamic
			progHeader.Memsz = _sizeOfDynamic
		}

		// Need to change GNU_RELRO type to SCE_RELRO. We also need to align the size so it and the data PT_LOAD are
		// contiguous.
		if progHeader.Type == elf.PT_GNU_RELRO {
			progHeader.Type = PT_SCE_RELRO

			// We need to fill the hole between the SCE_RELRO segment and the PT_LOAD segment for .data. Since
			// .data.sce_process_param should be the first thing in the data segment, we can use this to calculate.
			expandedSize := procParamSection.Offset - progHeader.Off
			progHeader.Filesz = expandedSize
			progHeader.Memsz = expandedSize
			progHeader.Align = 0x4000
		}

		// PT_LOAD's must be page aligned
		if progHeader.Type == elf.PT_LOAD {
			if progHeader.Align != 0x4000 {
				progHeader.Align = 0x4000
			}

			// PT_LOAD for .text will have it's size expanded to be contiguous with relro if needed
			if progHeader.Flags == (elf.PF_R | elf.PF_X) {
				if relroSection != nil {
					expandedSize := relroSection.Offset - progHeader.Off
					progHeader.Filesz = expandedSize
					progHeader.Memsz = expandedSize
				}
			}

			// PT_LOAD for data needs to be shifted to contain SCE specific data
			if progHeader.Flags == (elf.PF_R | elf.PF_W) {
				// We'll get the size by subtracting the proc param offset from data's offset so we get padding for free, which the
				// header size will not provide.
				dataSize := (dataSection.Offset - procParamSection.Offset) + dataSection.Size
				dataMemSize := (dataSection.Addr - procParamSection.Addr) + dataSection.Size

				// Also check for .bss - if it exists, factor it into the size
				if bssSection != nil {
					dataMemSize += (bssSection.Addr - (dataSection.Addr + dataSection.Size)) + bssSection.Size
				}

				progHeader.Off = procParamSection.Offset
				progHeader.Vaddr = procParamSection.Addr
				progHeader.Paddr = procParamSection.Addr
				progHeader.Filesz = dataSize
				progHeader.Memsz = dataMemSize
			}
		}
	}

	// Generate PS4-specific headers
	sceProcParamHeader := generateSceProcParamHeader(orbisElf.IsLibrary, procParamSection.Offset, procParamSection.Addr, procParamSection.Size)
	sceDynlibDataHeader := generateSceDynlibDataHeader(_offsetOfDynlibData, _sizeOfDynlibData)

	orbisElf.ProgramHeaders = append(orbisElf.ProgramHeaders, sceProcParamHeader, sceDynlibDataHeader)

	if !orbisElf.IsLibrary {
		interpHeader := generateInterpreterHeader(textSection.Offset)
		orbisElf.ProgramHeaders = append(orbisElf.ProgramHeaders, interpHeader)
	}

	sort.Sort(programHeaderList(orbisElf.ProgramHeaders))
	return nil
}

// OrbisElf.RewriteProgramHeaders iterates the list of new program headers and overwrites the ELF's program header table
// with the new headers. Returns an error if the write failed, nil otherwise.
func (orbisElf *OrbisElf) RewriteProgramHeaders() error {
	programHeaderTable := 0x40

	for i, progHeader := range orbisElf.ProgramHeaders {
		progHeaderBuff := new(bytes.Buffer)

		// Calculate the offset to write to by indexing into the program header table
		writeOffset := int64(programHeaderTable + (i * 0x38))

		alignment := progHeader.Align
		if uint32(progHeader.Type) == 0x7 {
			alignment = 0x20
		}

		// Write the structure into a buffer
		header := elf.Prog64{
			Type:   uint32(progHeader.Type),
			Flags:  uint32(progHeader.Flags),
			Off:    progHeader.Off,
			Vaddr:  progHeader.Vaddr,
			Paddr:  progHeader.Paddr,
			Filesz: progHeader.Filesz,
			Memsz:  progHeader.Memsz,
			Align:  alignment,
		}

		if err := binary.Write(progHeaderBuff, binary.LittleEndian, header); err != nil {
			return err
		}

		// Overwrite the entry in the file
		if _, err := orbisElf.FinalFile.WriteAt(progHeaderBuff.Bytes(), writeOffset); err != nil {
			return err
		}
	}

	return nil
}

// generateInterpreterHeader takes a given interpreterOffset and creates a program header for it. Returns the final program
// header.
func generateInterpreterHeader(interpreterOffset uint64) *elf.Prog {
	return &elf.Prog{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_INTERP,
			Flags: elf.PF_R,
			Vaddr: 0,
			Paddr: 0,

			// Interpreter will always be at offset 0 in the .text segment
			Off: interpreterOffset,

			Filesz: 0x15,
			Memsz:  0x15,
			Align:  1,
		},
	}
}

// generateSceProcParamHeader takes the given offset, virtualAddr, and size to create a new PT_SCE_PROC_PARAM program
// header. Returns the final program header.
func generateSceProcParamHeader(isLibrary bool, offset uint64, virtualAddr uint64, size uint64) *elf.Prog {
	segmentType := PT_SCE_PROC_PARAM

	if isLibrary {
		segmentType = PT_SCE_MODULE_PARAM
	}

	return &elf.Prog{
		ProgHeader: elf.ProgHeader{
			Type:   elf.ProgType(uint32(segmentType)),
			Flags:  elf.PF_R,
			Vaddr:  virtualAddr,
			Paddr:  virtualAddr,
			Off:    offset,
			Filesz: size,
			Memsz:  size,
			Align:  0x8,
		},
	}
}

// generateSceDynlibDataHeader takes the given offset and size to create a new PT_SCE_DYNLIBDATA program header. Returns
// the final program header.
func generateSceDynlibDataHeader(offset uint64, size uint64) *elf.Prog {
	return &elf.Prog{
		ProgHeader: elf.ProgHeader{
			Type:   PT_SCE_DYNLIBDATA,
			Flags:  elf.PF_R,
			Vaddr:  0,
			Paddr:  0,
			Off:    offset,
			Filesz: size,
			Memsz:  0,
			Align:  0x10,
		},
	}
}

////
// Sorting for program headers
////

// Create two priority mappings - one of program header types, and one of program header permissions for PT_LOAD.
// The first mapping will be used to re-order the table. The second mapping will be used when PT_LOAD is encountered,
// as we'll want an order defined for PT_LOAD as well.
var progHeaderTypeOrder = []elf.ProgType{
	elf.PT_LOAD,
	PT_SCE_RELRO,
	elf.PT_LOAD,
	PT_SCE_PROC_PARAM,
	PT_SCE_MODULE_PARAM,
	elf.PT_DYNAMIC,
	elf.PT_INTERP,
	elf.PT_TLS,
	PT_GNU_EH_FRAME,
	PT_SCE_DYNLIBDATA,
}

// getProgramHeaderPriority is a sorting function that will utilize the progHeaderTypeOrder mapping to determine an index
// for the program header, which will be utilized by the programHeaderList.Less() function for sorting.
func getProgramHeaderPriority(progHeaderOrder []elf.ProgType, progType elf.ProgType, progFlags elf.ProgFlag) int {
	for i, v := range progHeaderOrder {
		if v == progType {
			// Ensure with PT_LOAD that the flags are correct (ie. the second PT_LOAD should have R|W flags
			if v == elf.PT_LOAD && i == 0 && progFlags == elf.PF_R|elf.PF_W {
				continue
			}

			return i
		}
	}

	// Force unknown program headers to the end
	return math.MaxInt32
}

// Len is a standard function that just returns the length of the list.
func (s programHeaderList) Len() int {
	return len(s)
}

// Swap is a standard function that just swaps i and j elements in the list.
func (s programHeaderList) Swap(i int, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less uses the getProgramHeaderPriority() function to sort the list by priority.
func (s programHeaderList) Less(i int, j int) bool {
	return getProgramHeaderPriority(progHeaderTypeOrder, s[i].ProgHeader.Type, s[i].ProgHeader.Flags) < getProgramHeaderPriority(progHeaderTypeOrder, s[j].Type, s[j].Flags)
}

// align takes a given int and aligns it to a given value. Returns the aligned value.
func align(val uint64, align uint64) uint64 {
	return (val + (align - 1)) & ^(align - 1)
}
