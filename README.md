# Tool Documentation (create-fself)

## Summary
`create-fself` can be used to take 64-bit ELF files and produce **f**ake **S**igned **ELF**s that can be used on the PlayStation 4 (PS4). This includes `eboot.bin` files and Playstation Relocatable eXecutable (PRX) library files.

### Build
This tool is written in Golang. Commands should be the same between Windows and Linux assuming Golang is installed on the target system.

Building is straightforward, navigate to `/cmd/create-fself` and run `go build`.

There is a shell and batch build script to compile `create-fself` for all (Windows, Linux, and macOS).

### Usage
`create-fself` requires two arguments. The `-in` input ELF path, as well as either `-eboot` (for games/apps) or `-lib` (for libraries).

There are also additional optional arguments that can be used.

```
Usage of create-fself:
  -appversion int
        application version
  -authinfo string
        authentication info
  -eboot string
        produces an eboot, using the provided path for the output eboot
  -fwversion int
        firmware version
  -in input ELF path
        input ELF path to convert
  -lib string
        produces an sprx, using the provided path for final .prx file
  -libname string
        library name (ignored in create-eboot)
  -library-path string
        additional directories to search for .so files
  -out string
        output intermediate OELF path
  -paid int
        program authentication ID (default 4035225266123964433)
  -ptype string
        program type {fake, npdrm_exec, npdrm_dynlib, system_exec, system_dynlib, host_kernel, secure_module, secure_kernel}
  -sdkver int
        SDK version integer (default 72384769)
```

## Architecture

**cmd/create-fself/**
Tool main application code.

**pkg/oelf/**
Everything related to parsing and building Orbis ELFs (OELFs). These OELFs are not the final product, but an intermediate
between regular PC ELFs and the final fSELF the PS4 uses.

**pkg/fself/**
Everything related to parsing and building fSELFs. Most of this code is thanks to flatz' original python script.

**scripts/**
Build scripts for windows and linux.

**Makefile**
Makefile for building on linux.

***

## Utility functions
A list of the helper functions provided in Utils.go is provided below for convenience.

#### func (*OrbisElf) getFileOffsetBySectionName(string) (int64, error)
```golang
func (orbisElf *OrbisElf) getFileOffsetBySectionName(name string) (int64, error)
```
OrbisElf.getFileOffsetsBySectionName searches the section header table of the input ELF with the given name and returns that section's offset as well as error. If the section name does not exist, an offset of 0 and an error is returned. The offset and nil are returned otherwise.

#### func (*OrbisElf) getDynamicTag(elf.DynTag) (uint64, error)
```golang
func (orbisElf *OrbisElf) getDynamicTag(tag elf.DynTag) (uint64, error)
```
OrbisElf.getDynamicTag searches the dynamic table of the input ELF with the given tag and returns that tag's value as well as error. If the tag does not exist, or if the dynamic table cannot be found, a value of 0 and an error is returned. The value and nil are returned otherwise.

#### func (*OrbisElf) getSymbol(string) elf.Symbol
```golang
func (orbisElf *OrbisElf) getSymbol(name string) elf.Symbol
```
OrbisElf.getSymbol searches the symbol table of the input ELF with the given name and returns the corresponding elf.Symbol object. If the symbol does not exist, an empty elf.Symbol object is returned.

#### func (*OrbisElf) getProgramHeader(elf.ProgType, elf.ProgFlag) *elf.Prog
```golang
func (orbisElf *OrbisElf) getProgramHeader(headerType elf.ProgType, headerFlags elf.ProgFlag) *elf.Prog
```
OrbisElf.getProgramHeader searches the program header table of the input ELF with the given type and flags, and returns a pointer to that program header if it's found. If it cannot be found, a nil pointer is returned.

#### func checkIfLibraryContainsSymbol(*elf.File, string) (bool, error)
```golang
func checkIfLibraryContainsSymbol(library *elf.File, symbolName string) (bool, error)
```
checkIfLibraryContainsSymbol takes a given library and symbol name, and checks if the library contains that symbol. It returns a boolean of whether or not that library contains that symbol, as well as error. If we cannot get a libraries symbol list, false and an error is returned. Otherwise, the true or false and nil are returned.

#### func intToByteArray(int) []byte
```golang
func intToByteArray(value int) []byte
```
intToByteArray takes a given integer and writes it into a byte array (little endian) and returns it.

#### func writeNullBytes(uint64, uint64, *[]byte) uint64
```golang
func writeNullBytes(size uint64, align uint64, buffer *[]byte) uint64
```
writeNullBytes takes a given size and alignment, and uses that to write null padding to buffer. Returns the number of null bytes written.

#### func contains([]string, string) bool
```golang
func contains(slice []string, element string) bool
```
contains takes a given slice and element, and checks if the element is present within the slice. Returns true if it is present, false otherwise.

#### func NewOrderedMap() *OrderedMap
```golang
func NewOrderedMap() *OrderedMap
```
NewOrderedMap creates a new OrderedMap structure and returns it.

#### func (*OrderedMap) Get(interface{}) interface{}
```golang
func (orderedMap *OrderedMap) Get(key interface{}) interface{}
```
OrderedMap.Get uses a given key to return the corresponding mapping.

#### func (*OrderedMap) Set(interface{}, interface{})
```golang
func (orderedMap *OrderedMap) Set(key interface{}, value interface{})
```
OrderedMap.Set uses a given key to set that key's mapping to a given value.

#### func (*OrderedMap) Keys() []interface{}
```golang
func (orderedMap *OrderedMap) Keys() []interface{}
```
OrderedMap.Keys returns the current list of keys for the OrderedMap.

## Maintainers + Thanks
- Specter: Lead maintainer
- Kiwidog: Maintainer
- CrazyVoid: Maintainer
- flatz: SELF reversing/research
- sleirsgoevy: various fixes and improvements
- idc: various fixes and improvements
- lordfriky: macOS support