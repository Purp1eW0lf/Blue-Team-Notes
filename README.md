# Blue Team Notes
A collection of one-liners useful for blue team work. Tend to be Powershell. I've generally used these  one liners on [Velociraptor](https://www.velocidex.com)
, which lets me query a thousand endpoints at once.

I use _sysmon_ and _memetask_ as file or directory names in lieu of real file names, just replace the stupid names I've given with the files you actually need.

I've included screenshots where possible so you know what you're getting. Some screenshots will be from a Win machine, others may be from the Velociraptor GUI but they do the same thing as if you were on a host's command line.

## Contact me
If you see a mistake, or have an easier way to run a command then you're welcome to hit me up on [Twitter](https://twitter.com/Purp1eW0lf) or commit an issue here

### Get OS and Pwsh info
```powershell
$Bit = (get-wmiobject Win32_OperatingSystem).OSArchitecture ; $V = $host | select-object -property "Version" ; 
$Build = (Get-WmiObject -class Win32_OperatingSystem).Caption ; 
write-host "$env:computername is a $Bit $Build with Pwsh $V
```
![image](https://user-images.githubusercontent.com/44196051/119976027-75699300-bfae-11eb-8baa-42f9bbccbce2.png)

### Disconnect network adaptor, firewall the fuck out of an endpoint, and display warning box
This is a code-red command. Used to isolate a machine in an emergency.
Will isolate a machine and display a warning box. 
In the penultimate and final line, you can change the text and title that will pop up for the user
```powershell
New-NetFirewallRule -DisplayName "Block all outbound traffic" -Direction Outbound -Action Block | out-null; 
New-NetFirewallRule -DisplayName "Block all inbound traffic" -Direction Inbound -Action Block | out-null; 
$adapter = Get-NetAdapter|foreach { $_.Name } ; Disable-NetAdapter -Name "$adapter" -Confirm:$false; 
Add-Type -AssemblyName PresentationCore,PresentationFramework; 
[System.Windows.MessageBox]::Show('Your Computer has been Disconnected from the Internet for Security Issues. Please do not try to re-connect to the internet. Contact Security Helpdesk Desk ',' CompanyNameHere Security Alert',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information)
```
![image](https://user-images.githubusercontent.com/44196051/119979598-0e9aa880-bfb3-11eb-9882-08d02a0d3026.png)

### Is a specific process a running on a machine or not
```powershell
if (get-process | select-object -property ProcessName | where-object {$_.ProcessName -Match "memes"})
{Write-Host "memes successfully installed on " -NoNewline ; hostname} 
else {write-host "memes absent from " -NoNewline ; hostname}
```
Example of process that is absent
![image](https://user-images.githubusercontent.com/44196051/119976215-b1045d00-bfae-11eb-806c-49a62f5aab15.png)
Example of process that is present
![image](https://user-images.githubusercontent.com/44196051/119976374-ea3ccd00-bfae-11eb-94cd-37ed4233564d.png)


### Get process hash
Great to make malicious process stand out. If you want a different alogrithmn, just change it after `-Algorithmn` to something like `sha256` 
```powershell
foreach ($proc in Get-Process | select path -Unique)
{try { Get-FileHash $proc.path -Algorithm md5 -ErrorAction stop | Select-Object -property hash,path}catch{}}
```
![image](https://user-images.githubusercontent.com/44196051/119976802-8cf54b80-bfaf-11eb-82de-1a92bbcae4f9.png)

### Show all DLLs loaded with a process
```powershell
get-process -name "memestask" -module 
```
![image](https://user-images.githubusercontent.com/44196051/119976958-bdd58080-bfaf-11eb-8833-7fdf78045967.png)

Alternatively, pipe `|fl` and it will give a granularity to the DLLs

![image](https://user-images.githubusercontent.com/44196051/119977057-db0a4f00-bfaf-11eb-97ce-1e762088de8e.png)

### Recursively look for particular file types, and once you find the files get their hashes
This one-liner was a godsend during the Microsoft Exchange ballache back in early 2021
```powershell
Get-ChildItem -path "C:\windows\temp" -Recurse -Force -File -Include *.aspx, *.js, *.zip| Get-FileHash | Select-Object -property hash, path
```
![image](https://user-images.githubusercontent.com/44196051/119977578-887d6280-bfb0-11eb-9e56-fad64296128f.png)

Here's the a bash alternative
```bash
find . type f -exec sha256sum {} \; 2> /dev/null | grep -Ei 'asp|js' | sort
```
![image](https://user-images.githubusercontent.com/44196051/119977935-e7db7280-bfb0-11eb-8ee0-4da29089c736.png)

### To find the commands a task is running
Identify the user behind a command. Great at catching out malicious schtasks that perhaps are imitating names, or a process name
```powershell
Get-ScheduledTask | Select-Object -Property TaskName,author | fl 
```
![image](https://user-images.githubusercontent.com/44196051/119978821-01c98500-bfb2-11eb-9149-fc1a96a1af87.png)

Great one liner to find exactly WHAT a regular task is doing
```powershell
$task = Get-ScheduledTask | where TaskName -EQ "meme task"; 
$task.Actions
```
![image](https://user-images.githubusercontent.com/44196051/119979087-5f5dd180-bfb2-11eb-9d4d-bbbf66043535.png)

To stop the task
```powershell
Get-ScheduledTask "memetask" | Stop-ScheduledTask
```
### some WEF / WEC troubleshooting focused commands
I've tended to use these commands to troubleshoot Windows Event Forwarding
```powershell
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational | Format-List -Property * 
```
Specifically get the last time sysmon was written to
```powershell
(Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational).lastwritetime 
```
![image](https://user-images.githubusercontent.com/44196051/119979946-81a41f00-bfb3-11eb-8bc0-f2e893440b18.png)

Checks if the date was written recently, and if so, just print _sysmon working_ if not recent, then print the date last written. I've found sometimes that sometimes sysmon bugs out on a machine, and stops committing to logs. Change the number after `-ge` to be more flexible than the one day it currently compares to

```powershell
$b = (Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational).lastwritetime; 
$a = Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational | where-object {(new-timespan $_.LastWriteTime).days -ge 1}; 
if ($a -eq $null){Write-host "sysmon_working"} else {Write-host "$env:computername $b"}
```
![image](https://user-images.githubusercontent.com/44196051/119979908-72bd6c80-bfb3-11eb-9bff-856ebcc01375.png)

test the permissions of winrm - used to see windows event forwarding working, which uses winrm usually on endpoints and wecsvc account on servers
```cmd
netsh http show urlacl url=http://+:5985/wsman/ && netsh http show urlacl url=https://+:5986/wsman/
``` 
![image](https://user-images.githubusercontent.com/44196051/119980070-ae583680-bfb3-11eb-8da7-51d7e5393599.png)

### test if  files and directories are present or absent
This is great to just sanity check if things exist. Great when you're trying to check if files or directories have been left behind when you're cleaning stuff up.
You can use `test-path` to query REG, but even the Microsoft docs say that this can give inconsistent docs
```powershell
$a = Test-Path C:\windows\sysmon.exe; $b= Test-Path "C:\Windows\SysmonDrv.sys"; $c = test-path "C:\Program Files (x86)\sysmon"; $d = test-path "C:\Program Files\sysmon"; 
$env:computername; 
IF ($a -eq 'True') {Write-Host "C:\windows\sysmon.exe present"} ELSE {Write-Host "C:\windows\sysmon.exe absent"}; 
IF ($b -eq 'True') {Write-Host "C:\Windows\SysmonDrv.sys present"} ELSE {Write-Host "C:\Windows\SysmonDrv.sys absent"} ; 
IF ($c -eq 'True') {Write-Host "C:\Program Files (x86)\sysmon present"} ELSE {Write-Host "C:\Program Files (x86)\sysmon absent"}; 
IF ($d -eq 'True') {Write-Host "C:\Program Files\sysmon present"} ELSE {Write-Host "C:\Program Files\sysmon absent"}
```
![image](https://user-images.githubusercontent.com/44196051/119979754-443f9180-bfb3-11eb-9259-5409a0d98c04.png)

### get specific info about the full path binary that a process is running
```powershell
get-process -name "memetask" | select-object -property Name, Id, Path
```
![image](https://user-images.githubusercontent.com/44196051/119979341-bb285a80-bfb2-11eb-89a8-83b4c8f732c5.png)

### Give shell timestamp
For screenshots during IR, I like to have the date, time, and timezone in my shell
#### CMD
```cmd
setx prompt $D$S$T$H$H$H$S$B$S$P$_--$g
## all the H's are to backspace the stupid microsecond timestamp
## $_ and --$g seperate the date/time and path from the actual shell
# We make the use of the prompt command: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/prompt
##setx is in fact the command line command to write variables to the registery
##we are writing the prompt's new timestamp value in the cmd line into the reg
#so it stays perimnent, otherwise it would not stay in the cmdline when we closed it.
```
![image](https://user-images.githubusercontent.com/44196051/119978466-97b0e000-bfb1-11eb-83e1-022efba7dc96.png)

#### Pwsh
```powershell
###create a powershell profile, if it doesnt exist already
New-Item $Profile -ItemType file –Force
##open it in notepad to edit
function prompt{ "[$(Get-Date)]" +" | PS "+ "$(Get-Location) > "}
##risky move, need to tighten this up. Change your execution policy or it won't
#run the profile ps1
#run as powershell admin
Set-ExecutionPolicy RemoteSigned
```
![image](https://user-images.githubusercontent.com/44196051/119978226-486aaf80-bfb1-11eb-8e9e-52eabf2cde4c.png)

#### Bash
```bash
##open .bashrc
sudo nano .bashrc
#https://www.howtogeek.com/307701/how-to-customize-and-colorize-your-bash-prompt/
##date, time, colour, and parent+child directory only, and -> promptt
PS1='\[\033[00;35m\][`date  +"%d-%b-%y %T %Z"]` ${PWD#"${PWD%/*/*}/"}\n\[\033[01;36m\]-> \[\033[00;37m\]'
      ##begin purple  #year,month,day,time,timezone #show last 2 dir #next line, cyan,->prompt #back to normal white text
#restart the bash source
source ~/.bashrc
```
