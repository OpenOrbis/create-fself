package oelf

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

// OrbisElf groups together information important to the final converted Orbis ELF. It also contains information
// about the ELF file to convert to be accessed from OrbisElf's methods.
type OrbisElf struct {
	ProgramHeaders []elf.Prog64
	SectionHeaders []elf.Section64

	LibraryName            string
	ElfToConvertName       string
	ElfToConvert           *elf.File
	ModuleSymbolDictionary *OrderedMap
	WrittenBytes           int
	IsLibrary              bool

	FinalFile *os.File
}

// validateInputELF performs checks on the ELF to be converted. It checks the byte order, machine, class, and
// ensures the necessary segments exist. Returns an error if a check fails, nil otherwise.
func (orbisElf *OrbisElf) validateInputELF() error {
	// The input ELF must be little endian, and of AMD64 architecture
	if orbisElf.ElfToConvert.ByteOrder != binary.LittleEndian {
		return errors.New("byte order must be little endian")
	}

	if orbisElf.ElfToConvert.Machine != elf.EM_X86_64 {
		return errors.New("architecture must be x86_64 / AMD64")
	}

	if orbisElf.ElfToConvert.Class != elf.ELFCLASS64 {
		return errors.New("elf must be a 64-bit elf")
	}

	return nil
}

// CreateOrbisElf initiates an instance of OrbisElf and returns it
func CreateOrbisElf(isLib bool, inputFilePath string, outputFilePath string, libName string) (*OrbisElf, error) {
	fmt.Printf("0\n")
	// Open the ELF file to be converted, and create a file for the final Orbis ELF
	inputElf, err := elf.Open(inputFilePath)
	if err != nil {
		return nil, err
	}
	fmt.Printf("1\n")
	// Create final oelf file
	outputElf, err := os.Create(outputFilePath)
	if err != nil {
		return nil, err
	}
	fmt.Printf("2\n")
	orbisElf := OrbisElf{
		LibraryName:      libName,
		ElfToConvertName: inputFilePath,
		ElfToConvert:     inputElf,
		FinalFile:        outputElf,
	}
	fmt.Printf("3\n")
	// Validate ELF to convert before processing
	err = orbisElf.validateInputELF()
	if err != nil {
		return nil, err
	}
	fmt.Printf("4\n")
	// Copy contents of input file into output file
	inputFileBytes, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		return nil, err
	}
	fmt.Printf("5\n")
	writtenBytes, err := orbisElf.FinalFile.Write(inputFileBytes)
	if err != nil {
		return nil, err
	}
	fmt.Printf("6\n")
	orbisElf.IsLibrary = isLib
	orbisElf.WrittenBytes = writtenBytes
	return &orbisElf, nil
}
