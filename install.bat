@echo off

echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo @@@@@@@@@@@@@@@ YOU'RE NOW ENTERING THE DANGER ZONE @@@@@@@@@@@@@@@@@
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo.
echo UNLESS YOU TRUST YOUR ABILITY TO DO DAMAGE CONTROL, DO NOT PROCEED
echo.
echo This batch file replaces 5 core system files with our own version.
echo Things can go wrong horribly - commonly AV and WU interfering.
echo.
echo In particular, explorer.exe depends on these files. In the worst case
echo you wont be able to boot into desktop, you'll have to run sfc from
echo recovery.
echo.
echo Also, this script is not particularly smart either and might abort
echo with things half-installed in rare circumstances.
echo.
echo If something damages slshim installation (typically WU), it is usually
echo sufficient to run this batch file again (it is designed to handle
echo "reinstalls" too) to restore full functionality.
echo.
set /P c=Are you sure you want to proceed [Y/N]?

if /I "%c%" EQU "Y" goto i_know_what_i_am_doing
echo Stay safe now.
exit

:i_know_what_i_am_doing
rem
rem We're very careful to not burn bridges:
rem
rem We rename the replaced files as filename.slold
rem If some .slold file already exists, we use
rem random number as a suffix instead, and keep
rem the original .slold.
rem

echo.
echo === Copying and linking files ===
echo.


set sysdir=%windir%\system32
set offdir=microsoft shared\officesoftwareprotectionplatform
set office=%commonprogramfiles%\%offdir%

if "%PROCESSOR_ARCHITECTURE%"=="AMD64" goto 64BIT

rem
rem 32bits
rem

set bits=32
call:dofiles
goto initsvc

:64BIT
set bits=64
call:dofiles
set bits=32
set sysdir=%windir%\syswow64
set office=%commonprogramfiles(x86)%\%offdir%
call:dofiles
set bits=64
goto initsvc

:dofiles
echo Creating %sysdir%\slshim.dll ...
move %sysdir%\slshim.dll %windir%\Temp\slshim.%random% > nul 2> nul
copy slshim%bits%.dll %sysdir%\slshim.dll > nul
for %%d in (slc,slcext,sppc,sppcext,slwga) do (
	set dirname=%sysdir%
	set fname=%%d
	call:backupandlink
)
if not exist "%office%" exit /b
set dirname=%office%
set fname=osppc

:backupandlink
set fullname=%dirname%\%fname%
rem already linked to us, leave it
fsutil reparsepoint query "%fullname%.dll" > nul && exit /b
takeown /F "%fullname%.dll" > nul
icacls "%fullname%.dll" /Grant Administrators:F > nul
ren "%fullname%.dll" %fname%.slold 2> nul > nul
ren "%fullname%.dll" %fname%.%random% 2> nul > nul
rem if the above failed, mklink error will be visible
if "%fname%" == "osppc" (
	mklink "%fullname%.dll" %sysdir%\slshim.dll
) else (
	mklink "%fullname%.dll" slshim.dll
)
exit /b

:initsvc
rem We now force the service, because it is integral to deal with kernel
rem cache APIs (eg even notepad would cry otherwise)
echo.
echo === Creating kernel cache service ===
echo.
sc create SLShim binPath= "%%SystemRoot%%\system32\svchost.exe -k DcomLaunch" start= auto type= share group= Base
sc sidtype SLShim unrestricted
sc start SLShim > nul 2> nul
reg add HKLM\SYSTEM\CurrentControlSet\services\SLShim\Parameters /f /v ServiceDll /t REG_EXPAND_SZ /d %%SystemRoot%%\system32\slshim.dll
rundll32 slshim%bits%.dll SLShimSvcInit

echo.
echo === Disabling old SPPSVC services ===
echo.

reg add HKLM\SYSTEM\CurrentControlSet\services\sppuinotify /f /v Start /t REG_DWORD /d 4
reg add HKLM\SYSTEM\CurrentControlSet\services\sppsvc /f /v Start /t REG_DWORD /d 4
reg add HKLM\SYSTEM\CurrentControlSet\services\osppsvc /f /v Start /t REG_DWORD /d 4
reg import tokens.reg

echo ========
echo All done now. You'll have to reboot for changes to take effect.
echo Note that if anything above looks fishy (ie errors), run uninstall.bat.
echo If uninstall barks at you it can't find all backup files (partial install),
echo run echo `sfc /scannow` to repair your system.

