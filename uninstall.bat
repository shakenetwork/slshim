@echo off


set sysdir=%windir%\system32
set offdir=microsoft shared\officesoftwareprotectionplatform
set office=%commonprogramfiles%\%offdir%


if "%PROCESSOR_ARCHITECTURE%"=="AMD64" goto 64BIT

set bits=32
call:checkfiles
call:restorefiles
goto alldone

:64BIT
set bits=64
calL:checkfiles
call:restorefiles
set bits=32
set sysdir=%windir%\syswow64
set office=%commonprogramfiles(x86)%\%offdir%
call:checkfiles
call:restorefiles
goto alldone

:restorefiles
for %%d in (slc,slcext,sppc,sppcext,slwga) do (
	set dirname=%sysdir%
	set fname=%%d
	call:restorefile
)
if not exist "%office%" exit /b
set dirname=%office%
set fname=osppc
call:restorefile
exit /b

:checkfiles
echo === %bits%bit DLLs ===
rem
echo Checking...
for %%d in (slc,slcext,sppc,sppcext,slwga) do (
	set dirname=%sysdir%
	set fname=%%d
	call:checkfile
)
exit /b

:restorefile
set fullname=%dirname%\%fname%
echo - Restoring original %fname%.dll
move "%fullname%.dll" %windir%\Temp\%fname%.%random%.todel
ren "%fullname%.slold" %fname%.dll
icacls "%fullname%.dll" /setowner "NT SERVICE\TrustedInstaller"
exit /b

:checkfile
set fullname=%dirname%\%fname%
if exist "%fullname%.slold" exit /b
echo %fullname%.slold is missing.
echo This can mean two things:
echo.
echo Good: SLShim is not installed at all, hence no backups.
echo Bad: Something deleted the backups.
echo.
echo If you suspect the latter, run sfc /scannow, just to be sure.
echo slshim is designed to become inactive after succesful sfc run.
exit

:alldone

echo.
echo === Deleting SLShim service ====
echo.
rem We let the service live till the very end (so as to keep restored
rem policy backup pinned, despite kernel attempts to put something else there)
sc control SLShim 128
sc delete SLShim
move %windir%\system32\slshim.dll %windir%\Temp\slshim.%random%.todel > nul 2> nul
move %windir%\syswow64\slshim.dll %windir%\Temp\slshim.%random%.todel > nul 2> nul

echo.
echo === Re-enabling original SPPSVC ====
echo.

reg add HKLM\SYSTEM\CurrentControlSet\services\sppuinotify /f /v Start /t REG_DWORD /d 2
reg add HKLM\SYSTEM\CurrentControlSet\services\sppsvc /f /v Start /t REG_DWORD /d 3
reg add HKLM\SYSTEM\CurrentControlSet\services\osppsvc /f /v Start /t REG_DWORD /d 3
echo.
echo All done. Reboot now.
