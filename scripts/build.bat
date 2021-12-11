@ECHO OFF

CD ..\cmd\create-fself

REM Windows
SET GOOS=windows
IF NOT EXIST "%OO_PS4_TOOLCHAIN%\bin\windows" MKDIR %OO_PS4_TOOLCHAIN%\bin\windows
go.exe build -o create-fself.exe
COPY /Y create-fself.exe %OO_PS4_TOOLCHAIN%\bin\windows\create-fself.exe
DEL create-fself.exe

REM Linux
SET GOOS=linux
IF NOT EXIST "%OO_PS4_TOOLCHAIN%\bin\linux" MKDIR %OO_PS4_TOOLCHAIN%\bin\linux
go.exe build -o create-fself
COPY /Y create-fself %OO_PS4_TOOLCHAIN%\bin\linux\create-fself
DEL create-fself

REM MacOS
SET GOOS=darwin
IF NOT EXIST "%OO_PS4_TOOLCHAIN%\bin\macos" MKDIR %OO_PS4_TOOLCHAIN%\bin\macos
go.exe build -o create-fselfosx
COPY /Y create-fselfosx %OO_PS4_TOOLCHAIN%\bin\macos\create-fself
DEL create-fselfosx
