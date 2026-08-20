@echo off
REM Build seckill_native.dll with MSVC cl.exe (under vcvarsall).
REM (clang-cl 18 vs MSVC STL 14.44 mismatch forces cl.exe here.)
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (echo [build] vcvarsall failed & exit /b 1)

set JDK=C:\Program Files\Java\jdk-20

cl /nologo /LD /EHsc /O2 /utf-8 /W3 ^
  /I"%JDK%\include" /I"%JDK%\include\win32" ^
  native\jni_bridge.cpp native\interpreter_hook.cpp native\method_replace.cpp ^
  native\jvm_deopt.cpp native\memory_guard.cpp native\pristine_store.cpp ^
  native\hook_scanner.cpp native\anti_tamper.cpp native\dispatch_hook.cpp ^
  native\protect_class.cpp native\ghost_class.cpp native\process_protect.cpp ^
  native\etw_consumer.cpp ^
  /Fe:native\seckill_native.dll ^
  /link psapi.lib advapi32.lib

if errorlevel 1 (echo [build] cl failed & exit /b 1)
echo [build] OK native\seckill_native.dll
endlocal
