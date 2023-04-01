# Examples of Lateral Movement

## Preamble

> MITRE ATT&CK defines Lateral Movement [TA0008] : *“The adversary is trying to move through your environment”*

A number of examples of lateral movement showing the attacker’s machine laterally connecting to the target machine. Leveraging live Sysmon lab, [script here](https://gist.github.com/Purp1eW0lf/d669db5cfca9b020a7f7c982a8256deb)

Missing from this list:
+ Active Directory specific Pass-The-Ticket-like lateral movement and authentication manipulation
+ Cobalt Strike named pipe lateral movement & code execution.
+ Other C2 specific lateral movement

Screenshots detail both defender and attacker perspective
+ Left hand side: target machine’s processes (via Sysmon Lab)
+ Right hand: adversarial machine deploying malicious lateral movement. 

The parent & child processes detailed below reflect what will be observed via sysmon and most EDRs
```powershell
Parent Process
-->> Child Process
```

## Impacket [[S0357](https://attack.mitre.org/software/S0357/)]
> “Impacket is an open source collection of modules written in Python for programmatically constructing and manipulating network protocols. Impacket contains several tools for remote service execution, Kerberos manipulation, Windows credential dumping, packet sniffing, and relay attacks”

For more of an indepth blue team / defender discussion on Impacket, see 13cubed's resources:
+ https://www.youtube.com/watch?v=UMogme3rDRA
+ https://www.13cubed.com/downloads/impacket_exec_commands_cheat_sheet.pdf

### Impacket-AtExec 
Lateral movement and lateral code execution via Scheduled Tasks.
+ The scheduled task does not persist. 
+ It’s just a temporary mechanism for the adversary to run commands from their attacker machine on the target machine

![image](https://user-images.githubusercontent.com/44196051/227605749-8caac9ef-a39d-44c9-a6a3-1815f28be9d5.png)

```powershell
ParentCommandLine: C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
-->>>> Child CommandLine: cmd.exe /C whoami > C:\Windows\Temp\vTdWceeI.tmp 2>&1
ParentCommandLine: cmd.exe /C whoami > C:\Windows\Temp\vTdWceeI.tmp 2>&1
-->>>> CommandLine: whoami
```

May also see taskeng.exe associated with AtExec. Something like:

`taskeng.exe {AFA79333-694C-4BEE-910E-E57D9A3518F6} S-1-5-18:NT AUTHORITY\System:Service:`


### Impacket-DComExec
Lateral movement and lateral code execution via Dcom
+ Less commonly seen, to be honest

```powershell
CommandLine: C:\Windows\system32\mmc.exe -Embedding
ParentCommandLine: C:\Windows\system32\mmc.exe -Embedding
-->>>> Child CommandLine: "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__16745 2>&1
ParentCommandLine: C:\Windows\system32\mmc.exe
-->>>> Child CommandLine: "C:\Windows\System32\cmd.exe" /Q /c whoami 1> \\127.0.0.1\ADMIN$\__16745 2>&1
ParentCommandLine: "C:\Windows\System32\cmd.exe" /Q /c whoami 1> \\127.0.0.1\ADMIN$\__16745 2>&1
-->>>> Child CommandLine: C:\Windows\System32\whoami.exe
```

#### Alternate DComexec objects
Has other ‘objects’ it can deploy, for example `-object ShellBrowserWindow` which produces unique Processes

![image](https://user-images.githubusercontent.com/44196051/227606393-8e8cf964-0640-486d-b112-001bd044a8c9.png)

```powershell
CommandLine: C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c08afd90-f2a1-11d1-8455-00a0c91f3880} -Embedding
ParentCommandLine: C:\Windows\Explorer.EXE
-->>>> CommandLine: "C:\Windows\System32\cmd.exe" /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__16745 2>&1
```

On [research](https://strontic.github.io/xcyclopedia/library/clsid_c08afd90-f2a1-11d1-8455-00a0c91f3880.html), the above CLSID from rundll32 is associated with COM, giving a tell-tale sign for an investigator that DCom lateral movement may have occurred

### Impacket-PsExec
Connect from attacker linux machine via impacket-psexec. 
+ Behaves similarly to the legitimate PsExec, but renames the binaries and services

![image](https://user-images.githubusercontent.com/44196051/227606642-b8bd5d50-d54a-4443-81af-c1834f23a770.png)

```powershell
ParentCommandLine: C:\Windows\system32\services.exe
-->>>> CommandLine: C:\Windows\NiqSKfKd.exe
ParentCommandLine: C:\Windows\AbYDWdAI.exe
-->>>> Child CommandLine: cmd.exe
ParentCommandLine: cmd.exe
-->>>> Child CommandLine: whoami
```

### Impacket-SMBExec
Lateral movement and lateral code execution via SMB.
+ The temporary files ‘written’ via re-direction to the SMB share are just a temporary mechanism for the adversary to deploy commands and read the output. 
+ Notice that whilst the target machine on the right hand side details processes with execute.bat, 127.0.0.1, and more, the actual attacking machine on the right hand side details none of this, 
  + Instead, the attacker machine simply deploys their command and receives the output. The script is doing all the hard work for them of leveraging and re-directing files via SMB shares. 

![image](https://user-images.githubusercontent.com/44196051/227607031-cda308fc-11f6-4455-bac1-b4d5f70bdb3e.png)

```powershell
ParentCommandLine: C:\Windows\system32\services.exe
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
ParentCommandLine: C:\Windows\system32\cmd.exe /Q /c echo cd  ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe  /Q /c C:\Windows\TEMP\execute.bat
ParentCommandLine: C:\Windows\system32\cmd.exe /Q /c echo whoami ^> \\127.0.0.1\C$\__output 2^>^&1 > C:\Windows\TEMP\execute.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\execute.bat & del C:\Windows\TEMP\execute.bat
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe  /Q /c C:\Windows\TEMP\execute.bat
ParentCommandLine: C:\Windows\system32\cmd.exe  /Q /c C:\Windows\TEMP\execute.bat
-->>>> Child CommandLine: whoami
```

### Impacket-WMIExec
Lateral movement and lateral code execution via WMIC. 

![image](https://user-images.githubusercontent.com/44196051/227607167-f7759c67-746a-4065-ba8d-a86d80bdb0b8.png)

```powershell
ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe
-->>>> Child CommandLine: cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__1674554886.2833474 2>&1
ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe
-->>>> Child CommandLine: cmd.exe /Q /c cd  1> \\127.0.0.1\ADMIN$\__1674554886.2833474 2>&1
ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe
-->>>> CommandLine: cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1674554886.2833474 2>&1
ParentCommandLine: cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1674554886.2833474 2>&1
-->>>>  CommandLine: whoami
```
## CrackMapExec [[S0488](https://attack.mitre.org/software/S0488/)]
> “CrackMapExec, or CME, is a post-exploitation tool developed in Python and designed for penetration testing against networks. CrackMapExec collects Active Directory information to conduct lateral movement through targeted networks”. CrackMapExec allows a threat actor to connect from their linux machine to a windows machine via SMB, WinRM, RDP, MSSQL, and more.

Notice that the threat actor on the right hand side does not need to run anything complicated with share re-direction

Similar to Impacket-SMBExec, CrackMapExec’s modules are doing all of the hard work so all the threat actor has to do is deploy their command and then read the output of their command . 

![image](https://user-images.githubusercontent.com/44196051/227607453-6bc32d5c-3c3a-479c-9c61-2e89d6479fe6.png)

```powershell
ParentCommandLine: C:\Windows\system32\services.exe
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe /Q /c echo whoami ^> \\127.0.0.1\C$\dTqCsv 2^>^&1 > C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c del C:\Windows\TEMP\ZubJCr.bat
ParentCommandLine: C:\Windows\system32\cmd.exe /Q /c echo whoami ^> \\127.0.0.1\C$\dTqCsv 2^>^&1 > C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c del C:\Windows\TEMP\ZubJCr.bat
-->>>> ChildCommandLine: C:\Windows\system32\cmd.exe  /Q /c C:\Windows\TEMP\ZubJCr.bat
ParentCommandLine: C:\Windows\system32\cmd.exe  /Q /c C:\Windows\TEMP\ZubJCr.bat
-->>>> CommandLine: whoami
ParentCommandLine: C:\Windows\system32\cmd.exe /Q /c echo whoami ^> \\127.0.0.1\C$\dTqCsv 2^>^&1 > C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\ZubJCr.bat & C:\Windows\system32\cmd.exe /Q /c del C:\Windows\TEMP\ZubJCr.bat
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe  /Q /c del 
```

#### CrackMapExec Modules
In addition, it has a number of built in modules, that allow threat actors to simply select the name of the module to detonate complex adversarial activities - such as LSASS dumping

+ For more on CrackMapExec’s modules, see their [documentation](https://wiki.porchetta.industries/)

An example of a module here is `handlekatz`

![image](https://user-images.githubusercontent.com/44196051/227607802-ac39c89f-bb71-4187-869e-a274b8f64943.png)


```powershell
# writes file to disk
Type: File Create
TargetFilename: C:\Windows\Temp\handlekatz.exe

ParentCommandLine: C:\Windows\system32\services.exe
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe /Q /c echo tasklist /v /fo csv | findstr /i "lsass" ^> \\127.0.0.1\C$\MsFXVT 2^>^&1 > C:\Windows\TEMP\iBfpLd.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\iBfpLd.bat & C:\Windows\system32\cmd.exe /Q /c del C:\Windows\TEMP\iBfpLd.bat
ParentCommandLine: C:\Windows\system32\cmd.exe /Q /c echo tasklist /v /fo csv | findstr /i "lsass" ^> \\127.0.0.1\C$\MsFXVT 2^>^&1 > C:\Windows\TEMP\iBfpLd.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\TEMP\iBfpLd.bat & C:\Windows\system32\cmd.exe /Q /c del C:\Windows\TEMP\iBfpLd.bat
-->>>> Child CommandLine: C:\Windows\system32\cmd.exe  /S /D /c" echo tasklist /v /fo csv "
```
## Legitimate Windows Functionality
Adversaries can leverage built-in functionality of a Windows machine to achieve lateral movement.

### WinRM [[T1021.006](https://attack.mitre.org/techniques/T1021/006/)]
Similar to SSH, but in PowerShell. 
* Less commonly used, but have observed it in the wild before. 

WinRM is often not enabled by default. So look for enabling commands like:

```powershell
#as Admin
Enable-PSRemoting -force
winrm quickconfig
```

![image](https://user-images.githubusercontent.com/44196051/227608194-684b6db9-0782-41ff-9e40-3120bdd1ef60.png)

```powershell
ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
-->>>> Child CommandLine: "C:\Windows\system32\whoami.exe"
```

### PsExec [[S0029](https://attack.mitre.org/software/S0029/)]

> PsExec is a free Microsoft tool that can be used to execute a program on another computer. It is used by IT administrators and attackers.“ PsExec is a legitimate executable for remotely connecting to machines. PSEXESVC.exe is the reciprocating agent created on the target machine (read more here)

It is difficult to differentiate when PsExec is being used legitimately by a sysadmin, or abused by an adversary.
+ Contextualising PsExec with other detections, artefacts, and wider telemetry will help corroborate if PsExec is a true or false positive in the wild. 
+ There are a number of PsExec-like alternates - such as [PAExec](https://github.com/poweradminllc/PAExec)

![image](https://user-images.githubusercontent.com/44196051/227608622-335fb15b-37e4-4aee-b9e8-6accf22bdf0a.png)

```powershell
Type: File Create
TargetFilename: C:\Windows\PSEXESVC.exe

ParentCommandLine: C:\Windows\system32\services.exe
-->>>> Child CommandLine: C:\Windows\PSEXESVC.exe
ParentCommandLine: C:\Windows\PSEXESVC.exe
-->>>> Child CommandLine: "cmd"
ParentImage: C:\Windows\System32\cmd.exe
-->>>> Child CommandLine: whoami
```

### RDP [[T1021.001](https://attack.mitre.org/techniques/T1021/001/)]
> “Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS)”

Adversaries can move from linux attack machines to target windows machine, via RDP, which allows them to stop using the command line and start using a GUI as though they were sitting in front of the machine

RDP lateral movement may be preceded by Registry and PowerShell manipulation to enable RDP, so look for these commands:

```powershell
#Registry Manipulation
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

#Various firewall manipulations could be deployed
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
netsh firewall set service type = remotedesktop mode = enable
netsh advfirewall firewall add rule name="Open Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
```

![image](https://user-images.githubusercontent.com/44196051/227609036-31546aae-a197-4a5e-9049-df4fc8c9d8e0.png)

![image](https://user-images.githubusercontent.com/44196051/227609046-620feba4-73e5-4c6d-a4f7-12a247bc76cc.png)

```powershell
ParentCommandLine: C:\Windows\System32\svchost.exe -k NetworkService -s TermService
-->>>> CommandLine: C:\Windows\System32\rdpclip.exe
```

