@echo off
setlocal

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo [build] vcvarsall failed & exit /b 1)

set WDK=C:\Program Files (x86)\Windows Kits\10
set INC=%WDK%\Include\10.0.28000.0
set LIB=%WDK%\Lib\10.0.28000.0\km\x64

pushd native\driver

ml64 /nologo /Zi /c vmx_asm.asm
if errorlevel 1 (echo [build] ml64 failed & exit /b 1)
popd

cl /nologo /c /kernel /GS- /O2 /Zi /utf-8 /W3 /D_AMD64_ /D_WIN64 /DAMD64 /DNTDDI_VERSION=0x0A000000 /I"%INC%\km" /I"%INC%\shared" /I"%INC%\km\crt" /Fo:native\driver\tzd_ppl_drv.obj native\driver\tzd_ppl_drv.c
if errorlevel 1 (echo [build] cl failed & exit /b 1)

link /nologo /SUBSYSTEM:NATIVE,10 /DRIVER /ENTRY:DriverEntry /NODEFAULTLIB /MACHINE:X64 /DEBUG /PDB:"native\driver\tzd_ppl_drv.pdb" /LIBPATH:"%LIB%" /OUT:native\driver\tzd_ppl_drv.sys ntoskrnl.lib native\driver\tzd_ppl_drv.obj native\driver\vmx_asm.obj
if errorlevel 1 (echo [build] link failed & exit /b 1)

echo [build] OK: native\driver\tzd_ppl_drv.sys and native\driver\tzd_ppl_drv.pdb

endlocal