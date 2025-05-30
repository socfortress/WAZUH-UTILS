:: Simple script to run Sysmon Reload
:: The script executes a powershell script and appends output.
@ECHO OFF
ECHO.

Powershell.exe -executionpolicy ByPass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\sysmon_config_reload.ps1"

:Exit