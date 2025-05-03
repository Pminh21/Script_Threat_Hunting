@echo OFF
setlocal EnableDelayedExpansion
set "tool_folder=%~dp0"
set "flag2=%~2"
set "flag3=%~3"
set "notHidden=1 equ 1"
set "noGetEvt=1 equ 1"
:: ================================================================================
:: setup
:: ================================================================================
cd /d %~dp0

IF "%flag2%" EQU "hidden" (set "notHidden=1 equ 0" )
IF "%flag2%" EQU "getevt" (set "noGetEvt=1 equ 0" )

IF "%flag2%" EQU "hidden" (set "notHidden=1 equ 0" )
IF "%flag2%" EQU "getevt" (set "noGetEvt=1 equ 0" )

set "ldt=0000/00/00_00:00"
for /f "usebackq delims=" %%a in (`powershell -NoProfile -ExecutionPolicy Bypass -Command Get-Date -Format yyyy/MM/dd_HH:mm`) do set ldt=%%a

::check if already run successful
IF exist done.txt (
    for %%i in (done.txt) do (
        echo "[%ldt%] Identified previous successful tool (%%~ti) invocation! " > error.txt
    )
)

:: check false
:PreHunting
IF exist running.txt (
    echo "Already ran be4! Exiting..."
	type running.txt > error.txt
    echo "[%ldt%] Already ran be run! " > error.txt
    IF %notHidden% pause
    exit /b /1
)

:: cleanup and init
IF exist %tool_folder%\done.txt (
   del /s /f /q "%tool_folder%\done.txt"
)

if exist "%tool_folder%\log.txt" (
	del /s /f /q "%tool_folder%\log.txt"
)

echo.running at %ldt% > "%tool_folder%\running.txt"


:: ================================================================================
:: setup variables
:: ================================================================================

set "OSTYPE=x64"
IF /I "%PROCESSOR_ARCHITECTURE%" EQU "x86" (
    IF defined PROCESSOR_ARCHITEW6432 (
        set "OSTYPE=x64"
    )
) ELSE (
    set "OSTYPE=x64"
)

set verwin=6
for /f "tokens=4 delims=. " %%i in ('ver') do set verwin=%%i
set "gtrWin=%verwin% gtr 5"

if not defined SYSTEMDRIVE (
    echo.SYSTEMDRIVE not found >> %tool_folder%\error.txt
    set SYSTEMDRIVE=C:
)

set "ps_avai=0 equ 1"
if exist "%SYSTEMDRIVE%\Windows\system32\WindowsPowerShell\v1.0\powershell.exe" (
	%SYSTEMDRIVE%\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "try { Set-Content -Path 'PS1.OK' -Value 'Hello, World!' -ErrorAction Stop | Out-Null; Write-Host 'PowerShell OK' -ForegroundColor Green } catch { Write-Host 'PowerShell Error' -ForegroundColor Red }"
	if %errorlevel% equ 0 (
		if exist "PS1.OK" (
			set "ps_avai=1 equ 1"
			del /s /f /q "PS1.OK"
		) else (
			echo PowerShell Error 1 >> %tool_folder%\error.txt
		)
	) else (
		echo PowerShell Error 2 >> %tool_folder%\error.txt
	)
) else (
	echo PowerShell Not Exist >> %tool_folder%\error.txt
)

:: ================================================================================

echo.Setting up...

:: add path


set "localrar=%tool_folder%\%sdir%.rar"
set "localzip=%tool_folder%\%sdir%.zip"

@REM goto :TSETEST

:: disable win report
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2>> %tool_folder%\error.txt
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2>> %tool_folder%\error.txt

:: config sysinternal
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
%SYSTEMDRIVE%\Windows\system32\reg.exe IMPORT SysSuite\sysinternals.reg

set "totalproc=7"
set /a "totalproc=%totalproc%+1"
set "curproc=0"

echo.Make directory > %tool_folder%\log.txt
set sdir=samples_%COMPUTERNAME%
mkdir %sdir%
echo [+] check process_inject
if "%OSTYPE%" EQU "x64" (
    start "" /B /WAIT /REALTIME  "%~dp0util\hollows_hunter64.exe" /dir "%sdir%" >> "%sdir%\hollows_hunter.csv"
) else (
    start "" /B /WAIT /REALTIME "%~dp0util\hollows_hunter32.exe /dir "%sdir%" >> "%sdir%\hollows_hunter.csv"
)

:: ======== General ======== (1)

set /a "curproc=%curproc%+1"
if %notHidden% (
    echo [%curproc%/%totalproc%] General
)

:: echo. [+] Get Info
echo. [+] Get Info >> %tool_folder%\log.txt
echo.	- System Info...
echo.	- System Info... >> %tool_folder%\log.txt
start "" /B /WAIT /REALTIME %SYSTEMDRIVE%\Windows\system32\systeminfo.exe > "%sdir%\systeminfo.txt"
%SYSTEMDRIVE%\Windows\system32\ipconfig /all > "%sdir%\ipconfig_all.txt"

:: ======== Network ======== (2)
set /a "curproc=%curproc%+1"
if %notHidden% (
    echo [%curproc%/%totalproc%] Network
)
:: echo. [+] Get Network
echo. [+] Get Network >> %tool_folder%\log.txt
echo.	- Netstat...
echo.	- Netstat... >> %tool_folder%\log.txt
%SYSTEMDRIVE%\Windows\system32\netstat.exe -abno > "%sdir%\netstat_abno.txt" 2>> %tool_folder%\error.txt

echo.	- DNS Cache...
echo.	- DNS Cache... >> %tool_folder%\log.txt
%SYSTEMDRIVE%\Windows\system32\ipconfig.exe /displaydns > "%sdir%\dnscache.txt" 2>> %tool_folder%\error.txt

echo.	- Portproxy...
echo.	- Portproxy... >> %tool_folder%\log.txt
%SYSTEMDRIVE%\Windows\system32\netsh.exe interface portproxy show all > "%sdir%\portproxy.txt" 2>> %tool_folder%\error.txt

echo.	- Get Tcpvcon...
echo.	- Get Tcpvcon... >> %tool_folder%\log.txt
if "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\tcpvcon64.exe /accepteula -nobanner -a -n -c   /> "%sdir%\tcpview.csv" 2>> %tool_folder%\error.txt
) else (
     SysinternalsSuite\tcpvcon.exe /accepteula -nobanner -a -n -c > "%sdir%\tcpview.csv" 2>> %tool_folder%\error.txt
) 
%SYSTEMDRIVE%\Windows\System32\ping.exe -4 -n 3 "">nul

:: ======== User ======== (3)
set /a "curproc=%curproc%+1"
if %notHidden% (
    echo [%curproc%/%totalproc%] User
)
:: echo. [+] Get User
echo. [+] Get User >> %tool_folder%\log.txt

echo.	- Users info...
echo.	- Users info... >> %tool_folder%\log.txt
%SYSTEMDRIVE%\Windows\system32\net.exe localgroup users > "%sdir%\local_users_list.txt"
%SYSTEMDRIVE%\Windows\system32\net.exe localgroup administrators > "%sdir%\local_admin_list.txt"
dir /a /q /o:d "%USERPROFILE%\..\" > "%sdir%\local_users_dir_modified.txt"
dir /a /q /t:c /o:d "%USERPROFILE%\..\" > "%sdir%\local_users_dir_created.txt"

echo.	- Get PsLoggedon...
echo.	- Get PsLoggedon... >> %tool_folder%\log.txt
if "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\PsLoggedon64.exe /accepteula -nobanner > "%sdir%\logged_on_users.txt" 
) else (
     SysinternalsSuite\PsLoggedon.exe/accepteula -nobanner > "%sdir%\logged_on_users.txt" 
)

:: ======== Persistence ======== (4)
set /a "curproc=%curproc%+1"
if %notHidden% (
    echo [%curproc%/%totalproc%] Persistence
)
:: echo. [+] Get Persistence
echo. [+] Get Persistence >> %tool_folder%\log.txt

::displayswitch đổi chế độ màn hình là win + p
::atbroker rợ năng như Narrator, Magnifier, và các công cụ hỗ trợ người dùng khuyết tật.
::narrator.exe thuộc bộ công cụ trợ năng (Accessibility Features), được thiết kế để đọc to văn bản trên màn hình, hỗ trợ người dùng khiếm thị hoặc có khó khăn trong việc đọc
echo.	- Check backdoor...
echo.	- Check backdoor... >> %tool_folder%\log.txt
SysinternalsSuite\sigcheck.exe /accepteula  -nobanner  %SYSTEMDRIVE%\Windows\system32\displayswitch.exe > "%sdir%\sigcheck_system32_displayswitch.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula   -nobanner %SYSTEMDRIVE%\Windows\system32\atbroker.exe > "%sdir%\sigcheck_system32_atbroker.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\system32\narrator.exe  > "%sdir%\sigcheck_system32_narrator.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula  -nobanner  %SYSTEMDRIVE%\Windows\system32\magnify.exe  > "%sdir%\sigcheck_system32_magnify.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\system32\utilman.exe > "%sdir%\sigcheck_system32_utilman.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\system32\sethc.exe > "%sdir%\sigcheck_system32_sethc.txt" 2>> %tool_folder%\error.txt
SysinternalsSuite\sigcheck.exe /accepteula   -nobanner %SYSTEMDRIVE%\Windows\system32\osk.exe  > "%sdir%\sigcheck_system32_osk.txt" 2>> %tool_folder%\error.txt

if "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\displayswitch.exe > "%sdir%\sigcheck_syswow64_displayswitch.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\atbroker.exe > "%sdir%\sigcheck_syswow64_atbroker.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe  /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\narrator.exe   > "%sdir%\sigcheck_syswow64_narrator.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe /accepteula  -nobanner  %SYSTEMDRIVE%\Windows\syswow64\magnify.exe  > "%sdir%\sigcheck_syswow64_magnify.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe  /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\utilman.exe > "%sdir%\sigcheck_syswow64_utilman.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\sethc.exe> "%sdir%\sigcheck_syswow64_sethc.txt" 2>> %tool_folder%\error.txt
    SysinternalsSuite\sigcheck.exe  /accepteula  -nobanner %SYSTEMDRIVE%\Windows\syswow64\osk.exe  > "%sdir%\sigcheck_syswow64_osk.txt" 2>> %tool_folder%\error.txt
) 

echo.	- Get WMI...
echo.	- Get WMI... >> %tool_folder%\log.txt
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __EventConsumer get/format:list > "%sdir%\wmi_event_consumer.txt" 2>> %tool_folder%\error.txt
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __EventFilter get/format:list > "%sdir%\wmi_event_filter.txt" 2>> %tool_folder%\error.txt
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __FilterToConsumerBinding get/format:list > "%sdir%\wmi_filter_consumer_binding.txt" 2>> %tool_folder%\error.txt
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __TimerInstruction get/format:list > "%sdir%\wmi_timer_instruction.txt" 2>> %tool_folder%\error.txt

