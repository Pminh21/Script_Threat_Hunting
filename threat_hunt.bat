@echo off
setlocal EnableDelayedExpansion
set "tool_folder=%~dp0"
set "flag2=%~2"
set "flag3=%~3"
set "notHidden=1 equ 1"

:: Color settings for CLI
set "COLOR_TITLE=0E"  :: Yellow on black
set "COLOR_INFO=0B"   :: Cyan on black
set "COLOR_SUCCESS=0A" :: Green on black
set "COLOR_ERROR=0C"   :: Red on black
set "COLOR_HEADER=0D"  :: Purple on black
set "COLOR_NORMAL=07"  :: White on black

:: Initialize CLI display
cls
color %COLOR_HEADER%
echo ==============================================================================
echo                CyberVenator Suite Tool - Enhanced Interface                  
echo ==============================================================================
color %COLOR_NORMAL%
echo.

:: ================================================================================
:: MENU DISPLAY
:: ================================================================================
:Menu
cls
color %COLOR_HEADER%
echo ==============================================================================
echo                      CyberVenator Suite Tool - Main Menu                      
echo ==============================================================================
color %COLOR_TITLE%
echo Select a task to perform:
color %COLOR_NORMAL%
echo  1. Check Process Injection
echo  2. Collect General Information
echo  3. Collect Network Information
echo  4. Collect User Information
echo  5. Check Persistence Mechanisms
echo  6. Collect Process Information
echo  7. Collect Event Logs
echo  8. Collect File System Information
echo  9. Run All Tasks
echo  0. Exit
echo ==============================================================================
set /p choice=" Enter your choice (0-9): "
IF "%choice%"=="0" goto :EOF
IF "%choice%"=="1" goto :ProcessInjection
IF "%choice%"=="2" goto :General
IF "%choice%"=="3" goto :Network
IF "%choice%"=="4" goto :User
IF "%choice%"=="5" goto :Persistence
IF "%choice%"=="6" goto :Process
IF "%choice%"=="7" goto :EventLog
IF "%choice%"=="8" goto :Files
IF "%choice%"=="9" goto :RunAll
color %COLOR_ERROR%
echo Invalid choice! Please select a number from 0 to 9.
color %COLOR_NORMAL%
pause
goto Menu

:: ================================================================================
:: ENVIRONMENT SETUP
:: ================================================================================
:Setup
cd /d %~dp0
color %COLOR_INFO%
echo [%time%] Initializing environment...
color %COLOR_NORMAL%

:: Handle hidden flag
IF "%flag2%" EQU "hidden" set "notHidden=1 equ 0"

:: Get current timestamp
set "ldt=0000/00/00_00:00"
for /f "usebackq delims=" %%a in (`powershell -NoProfile -ExecutionPolicy Bypass -Command Get-Date -Format yyyy/MM/dd_HH:mm`) do set ldt=%%a

IF exist "%tool_folder%\done.txt" del /f /q "%tool_folder%\done.txt" 2>nul
:: Check if already run successfully
IF exist done.txt (
    for %%i in (done.txt) do (
        color %COLOR_ERROR%
        echo [%ldt%] Previous successful run detected (%%~ti^)!
        echo [%ldt%] Previous successful run detected (%%~ti^)! > "%tool_folder%\error.txt"
        color %COLOR_NORMAL%
        IF %notHidden% pause
        exit /b 1
    )
)

:: Check if script is already running
IF exist "%tool_folder%\running.txt" (
    color %COLOR_ERROR%
    echo [%ldt%] Script already running! Exiting...
    type "%tool_folder%\running.txt" > "%tool_folder%\error.txt"
    echo [%ldt%] Script already running! >> "%tool_folder%\error.txt"
    del /f /q "%tool_folder%\running.txt" 2>nul
    color %COLOR_NORMAL%
    IF %notHidden% pause
    exit /b 1
)

:: Cleanup previous files
IF exist "%tool_folder%\done.txt" del /s /f /q "%tool_folder%\done.txt"
IF exist "%tool_folder%\log.txt" del /s /f /q "%tool_folder%\log.txt"
echo running at %ldt% > "%tool_folder%\running.txt"

:: Detect OS architecture
set "OSTYPE=x64"
IF /I "%PROCESSOR_ARCHITECTURE%" EQU "x86" (
    IF not defined PROCESSOR_ARCHITEW6432 set "OSTYPE=x86"
)

:: Get Windows version
set verwin=6
for /f "tokens=4 delims=. " %%i in ('ver') do set verwin=%%i
set "gtrWin=%verwin% gtr 5"

:: Set system drive
IF not defined SYSTEMDRIVE (
    echo SYSTEMDRIVE not found >> "%tool_folder%\error.txt"
    set SYSTEMDRIVE=C:
)
set powershell_path=%SYSTEMDRIVE%\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

:: Verify PowerShell availability
set "ps_avai=0 equ 1"
IF exist "%powershell_path%" (
    %powershell_path% -NoProfile -Command "try { Set-Content -Path 'PS1.OK' -Value 'Hello, World!' -ErrorAction Stop | Out-Null; Write-Host 'PowerShell OK' -ForegroundColor Green } catch { Write-Host 'PowerShell Error' -ForegroundColor Red }"
    IF %errorlevel% equ 0 (
        IF exist "PS1.OK" (
            set "ps_avai=1 equ 1"
            del /s /f /q "PS1.OK"
        ) ELSE (
            echo PowerShell Error 1 >> "%tool_folder%\error.txt"
        )
    ) ELSE (
        echo PowerShell Error 2 >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo PowerShell Not Found >> "%tool_folder%\error.txt"
)

:: Disable Windows error reporting
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v DontShowUI /t REG_DWORD /d 1 /f 2>> "%tool_folder%\error.txt"

:: Configure Sysinternals
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
%SYSTEMDRIVE%\Windows\system32\reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f
%SYSTEMDRIVE%\Windows\system32\reg.exe IMPORT SysSuite\sysinternals.reg 2>> "%tool_folder%\error.txt"

:: Create output directory
set sdir=samples_%COMPUTERNAME%
mkdir "%sdir%" 2>> "%tool_folder%\error.txt"
echo [%time%] Created directory: %sdir% >> "%tool_folder%\log.txt"
goto :eof

:: ================================================================================
:: CyberVenator Suite TASKS
:: ================================================================================
:ProcessInjection
call :Setup
set "totalproc=8"
set "curproc=1"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Checking process injection...
color %COLOR_NORMAL%
echo [+] Checking process injection... >> "%tool_folder%\log.txt"
set "hollows_hunter_dump=%sdir%\hollows_hunter"
mkdir "%hollows_hunter_dump%"
IF "%OSTYPE%" EQU "x64" (
    start "" /B /WAIT /REALTIME "%~dp0util\hollows_hunter64.exe" /dir "%hollows_hunter_dump%" >> "%hollows_hunter_dump%\hollows_hunter.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] HollowsHunter failed. >> "%tool_folder%\error.txt"
) ELSE (
    start "" /B /WAIT /REALTIME "%~dp0util\hollows_hunter32.exe" /dir "%hollows_hunter_dump%" >> "%hollows_hunter_dump%\hollows_hunter.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] HollowsHunter failed. >> "%tool_folder%\error.txt"
)
goto :Cleanup

:General
call :Setup
set "totalproc=8"
set "curproc=2"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting general information...
color %COLOR_NORMAL%
echo [+] Collecting system info... >> "%tool_folder%\log.txt"
mkdir "%sdir%\General\"
start "" /B /WAIT /REALTIME %SYSTEMDRIVE%\Windows\system32\systeminfo.exe > "%sdir%\General\systeminfo.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] systeminfo failed. >> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\ipconfig /all > "%sdir%\General\ipconfig_all.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] ipconfig failed. >> "%tool_folder%\error.txt"
goto :Cleanup

:Network
call :Setup
set "totalproc=8"
set "curproc=3"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting network information...
color %COLOR_NORMAL%
echo [+] Collecting network data... >> "%tool_folder%\log.txt"
mkdir "%sdir%\Network"
%SYSTEMDRIVE%\Windows\system32\netstat.exe -abno > "%sdir%\Network\netstat_abno.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] netstat failed. >> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\ipconfig.exe /displaydns > "%sdir%\Network\dnscache.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] ipconfig /displaydns failed. >> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\netsh.exe interface portproxy show all > "%sdir%\Network\portproxy.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] netsh portproxy failed. >> "%tool_folder%\error.txt"
IF "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\tcpvcon64.exe /accepteula -nobanner -a -n -c > "%sdir%\Network\tcpview.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] tcpvcon64 failed. >> "%tool_folder%\error.txt"
) ELSE (
    SysinternalsSuite\tcpvcon.exe /accepteula -nobanner -a -n -c > "%sdir%\Network\tcpview.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] tcpvcon failed. >> "%tool_folder%\error.txt"
)
%SYSTEMDRIVE%\Windows\System32\ping.exe -4 -n 3 "" >nul 2>> "%tool_folder%\error.txt"
goto :Cleanup

:User
call :Setup
set "totalproc=8"
set "curproc=4"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting user information...
color %COLOR_NORMAL%
echo [+] Collecting user data... >> "%tool_folder%\log.txt"
mkdir "%sdir%\User"
%SYSTEMDRIVE%\Windows\system32\net.exe localgroup users > "%sdir%\User\local_users_list.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] net localgroup users failed. >> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\net.exe localgroup administrators > "%sdir%\User\local_admin_list.txt" 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 echo [%time%] net localgroup administrators failed. >> "%tool_folder%\error.txt"
dir /a /q /o:d "%USERPROFILE%\..\" > "%sdir%\User\local_users_dir_modified.txt" 2>> "%tool_folder%\error.txt"
dir /a /q /t:c /o:d "%USERPROFILE%\..\" > "%sdir%\User\local_users_dir_created.txt" 2>> "%tool_folder%\error.txt"
IF "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\PsLoggedon64.exe /accepteula -nobanner > "%sdir%\User\logged_on_users.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] PsLoggedon64 failed. >> "%tool_folder%\error.txt"
) ELSE (
    SysinternalsSuite\PsLoggedon.exe /accepteula -nobanner > "%sdir%\User\logged_on_users.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] PsLoggedon failed. >> "%tool_folder%\error.txt"
)
goto :Cleanup

:Persistence
call :Setup
set "totalproc=8"
set "curproc=5"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Checking persistence mechanisms...
color %COLOR_NORMAL%
echo [+] Checking persistence... >> "%tool_folder%\log.txt"
mkdir "%sdir%\Persistence"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\displayswitch.exe > "%sdir%\Persistence\sigcheck_system32_displayswitch.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\atbroker.exe > "%sdir%\Persistence\sigcheck_system32_atbroker.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\narrator.exe > "%sdir%\Persistence\sigcheck_system32_narrator.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\magnify.exe > "%sdir%\Persistence\sigcheck_system32_magnify.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\utilman.exe > "%sdir%\Persistence\sigcheck_system32_utilman.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\sethc.exe > "%sdir%\Persistence\sigcheck_system32_sethc.txt" 2>> "%tool_folder%\error.txt"
SysinternalsSuite\sigcheck.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\system32\osk.exe > "%sdir%\Persistence\sigcheck_system32_osk.txt" 2>> "%tool_folder%\error.txt"
IF "%OSTYPE%" EQU "x64" (
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\displayswitch.exe > "%sdir%\Persistence\sigcheck_syswow64_displayswitch.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\atbroker.exe > "%sdir%\Persistence\sigcheck_syswow64_atbroker.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\narrator.exe > "%sdir%\Persistence\sigcheck_syswow64_narrator.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\magnify.exe > "%sdir%\Persistence\sigcheck_syswow64_magnify.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\utilman.exe > "%sdir%\Persistence\sigcheck_syswow64_utilman.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\sethc.exe > "%sdir%\Persistence\sigcheck_syswow64_sethc.txt" 2>> "%tool_folder%\error.txt"
    SysinternalsSuite\sigcheck64.exe /accepteula -nobanner %SYSTEMDRIVE%\Windows\syswow64\osk.exe > "%sdir%\Persistence\sigcheck_syswow64_osk.txt" 2>> "%tool_folder%\error.txt"
)
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __EventConsumer get/format:list > "%sdir%\Persistence\wmi_event_consumer.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __EventFilter get/format:list > "%sdir%\Persistence\wmi_event_filter.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __FilterToConsumerBinding get/format:list > "%sdir%\Persistence\wmi_filter_consumer_binding.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\wbem\wmic.exe /namespace:\\root\subscription PATH __TimerInstruction get/format:list > "%sdir%\Persistence\wmi_timer_instruction.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom" > "%sdir%\Persistence\reg_AppCompatFlags_Custom.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB" > "%sdir%\Persistence\reg_AppCompatFlags_InstalledSDB.txt" 2>> "%tool_folder%\error.txt"
dir /a /t:c /q /o:d %SYSTEMDRIVE%\windows\AppPatch\Custom > "%sdir%\Persistence\shim_created.txt" 2>> "%tool_folder%\error.txt"
dir /a /q /o:d %SYSTEMDRIVE%\windows\AppPatch\Custom > "%sdir%\Persistence\shim_modified.txt" 2>> "%tool_folder%\error.txt"
dir /a /t:c /q /o:d %SYSTEMDRIVE%\windows\AppPatch\Custom\Custom64 > "%sdir%\Persistence\shimx64_created.txt" 2>> "%tool_folder%\error.txt"
dir /a /q /o:d %SYSTEMDRIVE%\windows\AppPatch\Custom\Custom64 > "%sdir%\Persistence\shimx64_modified.txt" 2>> "%tool_folder%\error.txt"
IF "%OSTYPE%" EQU "x64" (
    start "" /B /WAIT /REALTIME SysinternalsSuite\autorunsc64.exe /accepteula -nobanner -a * -c -h -s * -o "%sdir%\Persistence\autoruns.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] autorunsc64 failed. >> "%tool_folder%\error.txt"
) ELSE (
    start "" /B /WAIT /REALTIME SysinternalsSuite\autorunsc.exe /accepteula -nobanner -a * -c -h -s * -o "%sdir%\Persistence\autoruns.csv" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] autorunsc failed. >> "%tool_folder%\error.txt"
)
dir /a /t:c %SYSTEMDRIVE%\windows\psexesvc.exe > "%sdir%\Persistence\psexesvc_created.txt" 2>> "%tool_folder%\error.txt"
dir /a %SYSTEMDRIVE%\windows\psexesvc.exe > "%sdir%\Persistence\psexesvc_modified.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\sc.exe query PSEXESVC > "%sdir%\Persistence\psexesvc_service.txt" 2>> "%tool_folder%\error.txt"
%SYSTEMDRIVE%\Windows\system32\reg.exe query HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC > "%sdir%\Persistence\psexesvc_reg_svc.txt" 2>> "%tool_folder%\error.txt"
dir /a /t:c /o:d %SYSTEMDRIVE%\windows\tasks > "%sdir%\Persistence\windows_tasks_created.txt" 2>> "%tool_folder%\error.txt"
dir /a /t:c /o:d %SYSTEMDRIVE%\windows\system32\tasks > "%sdir%\Persistence\system32_tasks_created.txt" 2>> "%tool_folder%\error.txt"
goto :Cleanup

:Process
call :Setup
set "totalproc=8"
set "curproc=6"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting process information...
color %COLOR_NORMAL%
echo [+] Collecting process data... >> "%tool_folder%\log.txt"

mkdir "%sdir%\Process"
:: Collect process list using WMIC with error handling
set wmic_path=%SYSTEMDRIVE%\Windows\System32\wbem\wmic.exe
set process_txt="%sdir%\Process\process_txt.txt"
set process_csv="%sdir%\Process\process_csv.csv"
%wmic_path% /output:%process_txt% process list full >nul 2>> "%tool_folder%\error.txt"
if %errorlevel% neq 0 (
    color %COLOR_ERROR%
    echo [%time%] WMIC process list failed, retrying once... >> "%tool_folder%\log.txt"
    %wmic_path% /output:%process_txt% process list full >nul 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 (
        echo [%time%] WMIC process list failed again, skipping CSV generation. >> "%tool_folder%\error.txt"
        goto :ProcessNext
    )
)
if exist %process_txt% (
    %wmic_path% /output:%process_csv% process list full /format:csv >nul 2>> "%tool_folder%\error.txt"
    if %errorlevel% equ 0 (
        echo [+] Process list collected >> "%tool_folder%\log.txt"
    ) else (
        echo [%time%] Failed to generate CSV from process list. >> "%tool_folder%\error.txt"
    )
) else (
    echo [%time%] Process text file not created. >> "%tool_folder%\error.txt"
)

:: Collect process tree using pslist with error handling
IF "%OSTYPE%" EQU "x64" (
    start "" /B /WAIT /REALTIME SysinternalsSuite\pslist64.exe /accepteula -t > "%sdir%\Process\process_tree.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] pslist64 failed. >> "%tool_folder%\error.txt"
) ELSE (
    start "" /B /WAIT /REALTIME SysinternalsSuite\pslist.exe /accepteula -t > "%sdir%\Process\process_tree.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] pslist failed. >> "%tool_folder%\error.txt"
)

:: Collect system processes using PowerShell if available
IF %ps_avai% (
    "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId, CreationDate | Export-Csv -Path '%sdir%\Process\system_processes.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] PowerShell process collection failed. >> "%tool_folder%\error.txt"
)

:ProcessNext
goto :Cleanup

:EventLog
call :Setup
set "totalproc=8"
set "curproc=7"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting event logs...
color %COLOR_NORMAL%
echo [+] Collecting event logs... >> "%tool_folder%\log.txt"
mkdir "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt"
IF %gtrWin% (
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Security.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Security.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy Security.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Setup.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Setup.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy Setup.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Application.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Application.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy Application.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\System.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\System.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy System.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-LocalSessionManager.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-RemoteConnectionManager.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Windows PowerShell.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Windows PowerShell.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy Windows PowerShell.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy PowerShell-Operational.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-SmbClient%%4Security.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-SmbClient%%4Security.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy SmbClient-Security.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-SMBServer%%4Security.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-SMBServer%%4Security.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy SMBServer-Security.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Admin.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Admin.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy RemoteDesktopServices-Admin.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy RemoteDesktopServices-Operational.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TaskScheduler%%4Maintenance.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TaskScheduler%%4Maintenance.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TaskScheduler-Maintenance.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TaskScheduler%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TaskScheduler-Operational.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Admin.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%%4Admin.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-LocalSessionManager-Admin.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-RDPClient.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Admin.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Admin.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-RemoteConnectionManager-Admin.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy TerminalServices-RemoteConnectionManager-Operational.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-WinRM%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-WinRM%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy WinRM-Operational.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-WMI-Activity%%4Operational.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\Microsoft-Windows-WMI-Activity%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy WMI-Activity.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\OAlerts.evtx" copy "%SYSTEMDRIVE%\Windows\System32\Winevt\Logs\OAlerts.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy OAlerts.evtx >> "%tool_folder%\error.txt"
    IF EXIST "%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx" copy "%SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-Sysmon%%4Operational.evtx" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt" || echo [%time%] Failed to copy Sysmon-Operational.evtx >> "%tool_folder%\error.txt"
) ELSE (
    xcopy "%windir%\System32\config\*.evt" "%sdir%\win-event-log" 2>> "%tool_folder%\error.txt"
)
goto :Cleanup

:Files
call :Setup
set "totalproc=8"
set "curproc=8"
call :ShowProgress
color %COLOR_INFO%
IF %notHidden% echo [%curproc%/%totalproc%] Collecting file system information...
color %COLOR_NORMAL%
echo [+] Collecting file system data... >> "%tool_folder%\log.txt"
set sysdrive=%SYSTEMDRIVE%
mkdir "%sdir%\SystemFiles" 2>> "%tool_folder%\error.txt"
mkdir "%sdir%\SystemFiles\DefaultFolder" 2>> "%tool_folder%\error.txt"
mkdir "%sdir%\SystemFiles\UserFolder" 2>> "%tool_folder%\error.txt"

:: Collect system drive information
IF EXIST "%sysdrive%\" (
    dir "%sysdrive%\" /a:d /t:c /o:d > "%sdir%\SystemFiles\DefaultFolder\systemdrive.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] Failed to list system drive directories. >> "%tool_folder%\error.txt"
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\ -Directory -ErrorAction SilentlyContinue   | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\systemdrive.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell system drive collection failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] System drive not found. >> "%tool_folder%\error.txt"
)
:: Collect Windows directory information
IF EXIST "%sysdrive%\Windows\" (
    dir "%sysdrive%\Windows\" /a:d /t:c /o:d > "%sdir%\SystemFiles\DefaultFolder\Windows.txt" 2>> "%tool_folder%\error.txt"
    if %errorlevel% neq 0 echo [%time%] Failed to list Windows directories. >> "%tool_folder%\error.txt"
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\Windows\ -Directory -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\Windows.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell Windows collection failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] Windows directory not found. >> "%tool_folder%\error.txt"
)

:: Collect System32 information
IF EXIST "%sysdrive%\Windows\System32\" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\Windows\System32 -Force -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\System32.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell System32 collection failed. >> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\System32" > "%sdir%\SystemFiles\DefaultFolder\detail_system32.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 System32 failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\System32" > "%sdir%\SystemFiles\DefaultFolder\detail_system32.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck System32 failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] System32 directory not found. >> "%tool_folder%\error.txt"
)

:: Collect drivers information
IF EXIST "%sysdrive%\Windows\System32\drivers\" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\Windows\System32\drivers -Force -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\drivers.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell drivers collection failed. >> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\System32\drivers" > "%sdir%\SystemFiles\DefaultFolder\detail_drivers.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 drivers failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\System32\drivers" > "%sdir%\SystemFiles\DefaultFolder\detail_drivers.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck drivers failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] Drivers directory not found. >> "%tool_folder%\error.txt"
)

:: Collect temp information
IF EXIST "%sysdrive%\Windows\temp\" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\Windows\temp -Force -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\Windows_temp.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell temp collection failed. >> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\temp" > "%sdir%\SystemFiles\DefaultFolder\detail_Windows_temp.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 temp failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\temp" > "%sdir%\SystemFiles\DefaultFolder\detail_Windows_temp.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck temp failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] Temp directory not found. >> "%tool_folder%\error.txt"
)

:: Collect Public user information
IF EXIST "%sysdrive%\Users\Public\" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\Users\Public -Force -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\Public_user.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell Public user collection failed. >> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Users\Public" > "%sdir%\SystemFiles\DefaultFolder\detail_Public_user.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 Public user failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Users\Public" > "%sdir%\SystemFiles\DefaultFolder\detail_Public_user.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck Public user failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] Public directory not found. >> "%tool_folder%\error.txt"
)

:: Collect ProgramData information
IF EXIST "%sysdrive%\ProgramData\" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path $env:SystemDrive\ProgramData -Force -ErrorAction SilentlyContinue | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\ProgramData.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] PowerShell ProgramData collection failed. >> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\ProgramData" > "%sdir%\SystemFiles\DefaultFolder\detail_ProgramData.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 ProgramData failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\ProgramData" > "%sdir%\SystemFiles\DefaultFolder\detail_ProgramData.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck ProgramData failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] ProgramData directory not found. >> "%tool_folder%\error.txt"
)

:: Collect Program Files information
IF EXIST "%sysdrive%\Program Files\" (
     IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%sysdrive%\Program Files' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\Program_Files.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
    )
    IF "%OSTYPE%" EQU "x64" (
        "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Program Files" > "%sdir%\SystemFiles\DefaultFolder\detail_Program_Files.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck64 Program Files failed. >> "%tool_folder%\error.txt"
    ) ELSE (
        "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Program Files" > "%sdir%\SystemFiles\DefaultFolder\detail_Program_Files.csv" 2>> "%tool_folder%\error.txt"
        if %errorlevel% neq 0 echo [%time%] sigcheck Program Files failed. >> "%tool_folder%\error.txt"
    )
) ELSE (
    echo [%time%] Program Files directory not found. >> "%tool_folder%\error.txt"
)

:: Collect Program Files (x86) information (only for 64-bit)
IF "%OSTYPE%" EQU "x64" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%sysdrive%\Program Files (x86)' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\Program_Files_x86.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
    )
    "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Program Files (x86)" > "%sdir%\SystemFiles\DefaultFolder\detail_Program_Files_x86.csv" 2>> "%tool_folder%\error.txt"
)


:: Collect SysWOW64 information (only for 64-bit)
IF "%OSTYPE%" EQU "x64" (
    IF %ps_avai% (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%sysdrive%\Windows\SysWOW64' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\DefaultFolder\SysWOW64.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
    )
    "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%sysdrive%\Windows\SysWOW64" > "%sdir%\SystemFiles\DefaultFolder\detail_SysWOW64.csv" 2>> "%tool_folder%\error.txt"
)

:: Collect user directory information
set "user_dir=%systemdrive%\Users"
IF not %gtrWin% set "user_dir=%systemdrive%\Documents and Settings"
for /f "tokens=*" %%A in ('dir /b "%user_dir%"') do (
    mkdir "%sdir%\SystemFiles\UserFolder\%%A" 2>> "%tool_folder%\error.txt"
    IF %gtrWin% (
        IF EXIST "%user_dir%\%%A\AppData\Roaming" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\AppData\Roaming' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\roaming.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Roaming" > "%sdir%\SystemFiles\UserFolder\%%A\detail_roaming.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Roaming" > "%sdir%\SystemFiles\UserFolder\%%A\detail_roaming.csv" 2>> "%tool_folder%\error.txt"
            )
        )
        IF EXIST "%user_dir%\%%A\AppData\Local" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\AppData\Local' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\local.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Local" > "%sdir%\SystemFiles\UserFolder\%%A\detail_local.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Local" > "%sdir%\SystemFiles\UserFolder\%%A\detail_local.csv" 2>> "%tool_folder%\error.txt"
            )
        )
        IF EXIST "%user_dir%\%%A\AppData\Local\Temp" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\AppData\Local\Temp' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\temp.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Local\Temp" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\AppData\Local\Temp" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp.csv" 2>> "%tool_folder%\error.txt"
            )
        )
    ) ELSE (
        IF EXIST "%user_dir%\%%A\Application Data" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\Application Data' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\appdata.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Application Data" > "%sdir%\SystemFiles\UserFolder\%%A\detail_appdata.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Application Data" > "%sdir%\SystemFiles\UserFolder\%%A\detail_appdata.csv" 2>> "%tool_folder%\error.txt"
            )
        )
        IF EXIST "%user_dir%\%%A\Local Settings\Application Data" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\Local Settings\Application Data' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\local.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Application Data" > "%sdir%\SystemFiles\UserFolder\%%A\detail_local.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Application Data" > "%sdir%\SystemFiles\UserFolder\%%A\detail_local.csv" 2>> "%tool_folder%\error.txt"
            )
        )
        IF EXIST "%user_dir%\%%A\Local Settings\Temp" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\Local Settings\Temp' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\temp.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Temp" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Temp" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp.csv" 2>> "%tool_folder%\error.txt"
            )
        )
        IF EXIST "%user_dir%\%%A\Local Settings\Temporary Internet Files" (
            "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\Local Settings\Temporary Internet Files' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\temp_internet.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
            IF "%OSTYPE%"=="x64" (
                "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Temporary Internet Files" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp_internet.csv" 2>> "%tool_folder%\error.txt"
            ) ELSE (
                "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Local Settings\Temporary Internet Files" > "%sdir%\SystemFiles\UserFolder\%%A\detail_temp_internet.csv" 2>> "%tool_folder%\error.txt"
            )
        )
    )
    IF EXIST "%user_dir%\%%A\Downloads" (
        "%powershell_path%" -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%user_dir%\%%A\Downloads' -Force -ErrorAction SilentlyContinue; $files | Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, FullName | Sort-Object -Property LastWriteTime | Export-Csv -Path '%sdir%\SystemFiles\UserFolder\%%A\downloads.csv' -NoTypeInformation -Encoding UTF8" 2>> "%tool_folder%\error.txt"
        IF "%OSTYPE%"=="x64" (
            "%tool_folder%\SysinternalsSuite\sigcheck64.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Downloads" > "%sdir%\SystemFiles\UserFolder\%%A\detail_downloads.csv" 2>> "%tool_folder%\error.txt"
        ) ELSE (
            "%tool_folder%\SysinternalsSuite\sigcheck.exe" -accepteula -s -ct -h -a -nobanner "%user_dir%\%%A\Downloads" > "%sdir%\SystemFiles\UserFolder\%%A\detail_downloads.csv" 2>> "%tool_folder%\error.txt"
        )
    )
)
goto :Cleanup

:RunAll
call :Setup
set "totalproc=8"
set "curproc=0"
color %COLOR_HEADER%
echo ==============================================================================
echo                   Running All Tasks...
echo ==============================================================================
color %COLOR_NORMAL%
call :ProcessInjection
set /a curproc+=1
call :ShowProgress
call :General
set /a curproc+=1
call :ShowProgress
call :Network
set /a curproc+=1
call :ShowProgress
call :User
set /a curproc+=1
call :ShowProgress
call :Persistence
set /a curproc+=1
call :ShowProgress
call :Process
set /a curproc+=1
call :ShowProgress
call :EventLog
set /a curproc+=1
call :ShowProgress
call :Files
goto :Cleanup

:: ================================================================================
:: PROGRESS DISPLAY
:: ================================================================================
:ShowProgress
set /a "progress=(curproc*100)/totalproc"
set "progressBar="
for /L %%i in (1,1,!progress!) do set "progressBar=!progressBar!#"
for /L %%i in (!progress!,1,100) do set "progressBar=!progressBar!."
color %COLOR_INFO%
IF %notHidden% echo Progress: [!progressBar!] !progress!%%
color %COLOR_NORMAL%
goto :eof

:: ================================================================================
:: CLEANUP AND FILE LISTING
:: ================================================================================
:Cleanup
color %COLOR_INFO%
IF %notHidden% echo [%time%] Cleaning up...
color %COLOR_NORMAL%
echo [+] Cleaning up... >> "%tool_folder%\log.txt"
echo [%ldt%] Data collection completed > "%tool_folder%\done.txt"
IF exist "%tool_folder%\running.txt" del /f /q "%tool_folder%\running.txt" > nul
IF exist "%tool_folder%\log.txt" del /f /q "%tool_folder%\log.txt" > nul
IF exist "%tool_folder%\error.txt" (
    for %%i in ("%tool_folder%\error.txt") do IF %%~zi==0 del /f /q "%tool_folder%\error.txt" > nul
)

:: Display collected files
color %COLOR_HEADER%
echo ==============================================================================
echo                   Collected Files in %sdir%
echo ==============================================================================
color %COLOR_NORMAL%
IF exist "%sdir%" (
    dir "%sdir%" /a /s /t:c /o:d
    echo Results saved to: %tool_folder%\%sdir%
) ELSE (
    color %COLOR_ERROR%
    echo Output directory %sdir% not found!
    color %COLOR_NORMAL%
)

color %COLOR_SUCCESS%
echo ==============================================================================
echo                   Data Collection Completed Successfully!
echo ==============================================================================
color %COLOR_NORMAL%
IF %notHidden% pause
goto  :eof