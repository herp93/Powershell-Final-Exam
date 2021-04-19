#PowewerShell - Final Exam
#Student Name: Pa Chang Her
#Course #: ITNET-154
#Date: 4/18
##########################################################

#Question #1
#No need to add scripts for this question


#region Question #2
#submitted by Pa Chang Her
#date: 4/18
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Test-Connection -ComputerName DC2, CLIENT1
Get-DnsServerZone
Get-DnsServerResourceRecord -ZoneName "ITNET-154.pri"

#endregion 

#region Question #3
#submitted by Pa Chang Her
#date: 4/18
Add-WindowsFeature -IncludeManagementTools dhcp
netsh dhcp add securitygroups
Add-DhcpServerInDC
Set-ItemProperty `
        –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 `
        –Name ConfigurationState `
        –Value 2
 Add-DhcpServerv4Scope `
        -Name “192.168.20.0” `
        -StartRange 192.168.20.240 `
        -EndRange 192.168.20.250 `
        -SubnetMask 255.255.255.0 `
        -ComputerName DC1 `
        -LeaseDuration 8:0:0:0 `
        -verbose
 Set-DhcpServerv4OptionValue  `
        -ScopeId 192.168.20.0 `
        -ComputerName DC1.ITNET-154.pri `
        -DnsServer 192.168.20.101 `
        -DnsDomain itnet-154.pri `
        -Router 192.168.20.1 `
        -Verbose
Get-DhcpServerv4Scope | FL
Get-DhcpServerv4Lease -ScopeId 192.168.20.0
Test-NetConnection 192.168.20.103

#endregion

#region Question #4
#submitted by Pa Chang Her
#date: 4/18
New-ADOrganizationalUnit -Name DAs -Path "DC=ITNET-154, DC=pri"

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin1" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin1 `
-UserPrincipalName ("DomainAdmin1@ITNET-154.pri")

New-ADUser `
-AccountPassword (ConvertTo-SecureString "Password01" -AsPlainText -Force) `
-Name "DomainAdmin2" `
-Enabled $true `
-Path "CN=Users, DC=ITNET-154, DC=pri" `
-SamAccountName DomainAdmin2 `
-UserPrincipalName ("DomainAdmin2@ITNET-154.pri")

Add-ADGroupMember -Identity 'Domain Admins' -Members 'DomainAdmin1','DomainAdmin2'

#endregion

#region Question #5
#submitted by Pa Chang Her
#date: 4/18
New-ADOrganizationalUnit -Name Employees -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Workstations -Path "DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name "Member Servers" -Path "DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Employees, DDC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Employees, DC=ITNET-154, DC=pri"

New-ADOrganizationalUnit -Name Office -Path "OU=Workstations, DC=ITNET-154, DC=pri"
New-ADOrganizationalUnit -Name Factory -Path "OU=Workstations, DC=ITNET-154, DC=pri"

#endregion

#region Question #6 
#submitted by Pa Chang Her
#date: 4/18
New-ADOrganizationalUnit -Name TempEmployees -Path "DC=ITNET-154, DC=pri"

Import-Module ActiveDirectory
foreach ($i in 1..50)
{
$AccountName = "Worker{0:d1}" -f $i
$userprinciple = $AccountName + "@ITNET-154.pri"
$SecurePassword = "Password01" | ConvertTo-SecureString -AsPlainText -Force
New-ADUser -Name $AccountName -AccountPassword $SecurePassword -Path "OU=TempEmployees,DC=ITNET-154,DC=pri" -Enabled $true

}
#endregion

#region Question #7 
#submitted by Pa Chang Her
#date: 4/18
New-ADGroup “GG_Factory” -GroupScope Global -GroupCategory Security
Add-ADGroupMember “GG_Factory” -Members Worker1,Worker2,Worker3,Worker4,Worker5
Get-ADGroupMember -Identity GG_Factory

#endregion

#region Question #8
#submitted by Pa Chang Her
#date: 4/18
New-ADGroup “GG_Office” -GroupScope Global -GroupCategory Security
Add-ADGroupMember “GG_Office” -Members Worker6,Worker7,Worker8,Worker9,Worker10
Get-ADGroupMember -Identity GG_Office
#endregion

#region Question #9
#submitted by Pa Chang Her
#date: 4/18
Move-ADObject -Identity "CN=Worker1,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker2,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker3,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker4,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri" 
Move-ADObject -Identity "CN=Worker5,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Factory,OU=Employees,DC=ITNET-154,DC=pri" 

Move-ADObject -Identity "CN=Worker6,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker7,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker8,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"  
Move-ADObject -Identity "CN=Worker9,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Office,OU=Employees,DC=ITNET-154,DC=pri" 
Move-ADObject -Identity "CN=Worker10,OU=TempEmployees,DC=ITNET-154,DC=pri" -TargetPath "OU=Office,OU=Employees,DC=ITNET-154,DC=pri"

#endregion

#region Question #10
#submitted by Pa Chang Her
#date: 4/18
New-ADGroup “GG_AllEmployees” -GroupScope Global -GroupCategory Security
Add-ADGroupMember "GG_AllEmployees" -Members GG_Factory, GG_Office
Get-ADGroupMember -Identity GG_AllEmployees

#endregion 
