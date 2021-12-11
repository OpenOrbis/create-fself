// This file only contains the entry point, and calls into the Orbis ELF Builder to start generating an output ELF using
// the information passed by command line.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/OpenOrbis/create-fself/pkg/fself"
	"github.com/OpenOrbis/create-fself/pkg/oelf"
)

// errorExit function will print the given formatted error to stdout and exit immediately after.
func errorExit(format string, params ...interface{}) {
	fmt.Printf(format, params...)
	os.Exit(-1)
}

// check will check the error given by argument. If it's not nil, it will print the error to the console and the program
// will exit.
func check(err error) {
	if err != nil {
		errorExit("Failed to build FSELF: %s\n", err.Error())
	}
}

func main() {
	// Get the SDK path in the environment variables. If it's not set, we need to state so and bail because we *need* it
	sdkPath := os.Getenv("OO_PS4_TOOLCHAIN")

	if sdkPath == "" {
		errorExit("The 'OO_PS4_TOOLCHAIN' environment variable is not set. It must be set to the root directory of the toolchain.\n")
	}

	// Required flags
	inputFilePath := flag.String("in", "", "input ELF path")

	// Semi-optional flags (one must be specified)
	outEbootPath := flag.String("eboot", "", "eboot.bin output path")
	outLibPath := flag.String("lib", "", "library output path")

	// Optional flags
	outputFilePath := flag.String("out", "", "output OELF path")
	sdkVer := flag.Int("sdkver", 0x4508101, "SDK version integer")
	pType := flag.String("ptype", "", "program type {fake, npdrm_exec, npdrm_dynlib, system_exec, system_dynlib, host_kernel, secure_module, secure_kernel}")
	authInfo := flag.String("authinfo", "", "authentication info")
	paid := flag.Int64("paid", 0x3800000000000011, "program authentication ID")
	appVer := flag.Int64("appversion", 0, "application version")
	fwVer := flag.Int64("fwversion", 0, "firmware version")
	libName := flag.String("libname", "", "library name (ignored in create-eboot)")
	libPath := flag.String("library-path", "", "additional directories to search for .so files")

	flag.Parse()

	// Check for required flags
	if *inputFilePath == "" {
		errorExit("Input file not specified, try -in=[input ELF path]\n")
	}

	// Check that at one (and only one) of -eboot or -lib is set
	if *outEbootPath != "" && *outLibPath != "" {
		errorExit("Invalid to have an output eboot path and output library path at the same time.\n")
	}

	if *outEbootPath == "" && *outLibPath == "" {
		errorExit("Need either an output eboot path or output library path.\n")
	}

	isLib := false
	if *outLibPath != "" {
		isLib = true
	}

	// Check if outputFilePath is set, if it's not, we'll set it but clean it up later
	isOelfTemp := false

	if *outputFilePath == "" {
		*outputFilePath = strings.Split(*inputFilePath, ".")[0] + ".oelf"
		isOelfTemp = true
	}

	// Start generating final oelf file
	orbisElf, err := oelf.CreateOrbisElf(isLib, *inputFilePath, *outputFilePath, *libName)
	check(err)

	// Create the .sce_dynlib_data segment onto the end of the file
	err = orbisElf.GenerateDynlibData(sdkPath, *libPath)
	check(err)

	// Generate updated program headers
	err = orbisElf.GenerateProgramHeaders()
	check(err)

	// Overwrite ELF file header with PS4-ified values, as well as the SDK version in .sce_process_param/.sce_module_param
	err = orbisElf.RewriteELFHeader()
	check(err)

	err = orbisElf.RewriteSDKVersion(*sdkVer)
	check(err)

	// Overwrite program header table
	err = orbisElf.RewriteProgramHeaders()
	check(err)

	// Commit
	err = orbisElf.FinalFile.Close()
	check(err)

	// Create FSELF
	fselfInputPath := *outputFilePath
	fselfOutputPath := ""

	if *outEbootPath != "" {
		fselfOutputPath = *outEbootPath
	} else {
		fselfOutputPath = *outLibPath
	}

	err = fself.CreateFSELF(isLib, fselfInputPath, fselfOutputPath, *paid, *pType, *appVer, *fwVer, *authInfo)

	// Cleanup oelf file if needed
	if isOelfTemp {
		_ = os.Remove(*outputFilePath)
	}
}
