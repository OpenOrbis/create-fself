module create-fself

go 1.17

require (
	github.com/OpenOrbis/create-fself/pkg/fself v0.0.0-00010101000000-000000000000
	github.com/OpenOrbis/create-fself/pkg/oelf v0.0.0-00010101000000-000000000000
)

replace (
	github.com/OpenOrbis/create-fself/pkg/fself => ..\..\pkg\fself
	github.com/OpenOrbis/create-fself/pkg/oelf => ..\..\\pkg\oelf
)
