<#
.SYNOPSIS
    Automated Domain Controller setup for homelab environment.

.DESCRIPTION
    This script installs and configures Active Directory Domain Services,
    DNS, and DHCP on a Windows Server 2022 system. It creates a new forest
    named homelab.local with basic OU structure, test users, and groups.

.NOTES
    Author: Your Name
    Date: November 2025
    Requirements: Windows Server 2022, Administrator privileges
    
.EXAMPLE
    .\01-Initialize-DomainController.ps1
#>

#Requires -RunAsAdministrator

# Script configuration
$ErrorActionPreference = "Stop"
$VerbosePreference = "Continue"

# Domain configuration
$Config = @{
    DomainName = "homelab.local"
    DomainNetBIOS = "HOMELAB"
    DHCPScopeStart = "192.168.100.100"
    DHCPScopeEnd = "192.168.100.200"
    DHCPSubnet = "192.168.100.0"
    DHCPSubnetMask = "255.255.255.0"
    Gateway = "192.168.100.1"
    DNSServer = "192.168.100.10"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Domain Controller Setup Script" -ForegroundColor Cyan
Write-Host "  Domain: $($Config.DomainName)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Function to check if reboot is required
function Test-RebootRequired {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    return $false
}

# Step 1: Install AD DS Role
Write-Host "[1/7] Installing Active Directory Domain Services..." -ForegroundColor Yellow
if ((Get-WindowsFeature -Name AD-Domain-Services).InstallState -ne "Installed") {
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Write-Host "  ✓ AD DS installed successfully" -ForegroundColor Green
} else {
    Write-Host "  ✓ AD DS already installed" -ForegroundColor Green
}

# Step 2: Promote to Domain Controller
Write-Host "`n[2/7] Checking if server is already a Domain Controller..." -ForegroundColor Yellow
try {
    $Domain = Get-ADDomain -ErrorAction SilentlyContinue
    Write-Host "  ✓ Server is already a Domain Controller for domain: $($Domain.DNSRoot)" -ForegroundColor Green
    $AlreadyDC = $true
} catch {
    $AlreadyDC = $false
    Write-Host "  → Server is not a Domain Controller. Promoting..." -ForegroundColor Cyan
    
    # Get DSRM password
    $DSRMPassword = Read-Host -AsSecureString -Prompt "  Enter Directory Services Restore Mode (DSRM) password"
    
    # Promote to DC
    Write-Host "  → Installing Active Directory Forest..." -ForegroundColor Cyan
    Write-Host "    This will take several minutes and will restart the server..." -ForegroundColor Yellow
    
    Install-ADDSForest `
        -DomainName $Config.DomainName `
        -DomainNetbiosName $Config.DomainNetBIOS `
        -InstallDns `
        -SafeModeAdministratorPassword $DSRMPassword `
        -Force `
        -NoRebootOnCompletion:$false
    
    # Script will not reach here as server will reboot
    Write-Host "`n  Server is restarting..." -ForegroundColor Yellow
    Write-Host "  Please run this script again after restart to complete setup.`n" -ForegroundColor Cyan
    exit 0
}

# If we reach here, the server is already a DC
# Continue with post-installation configuration

# Step 3: Configure DNS Forwarders
Write-Host "`n[3/7] Configuring DNS forwarders..." -ForegroundColor Yellow
$Forwarders = Get-DnsServerForwarder
if ($Forwarders.IPAddress.IPAddressToString -notcontains "8.8.8.8") {
    Add-DnsServerForwarder -IPAddress "8.8.8.8"
    Write-Host "  ✓ Added Google DNS (8.8.8.8)" -ForegroundColor Green
}
if ($Forwarders.IPAddress.IPAddressToString -notcontains "1.1.1.1") {
    Add-DnsServerForwarder -IPAddress "1.1.1.1"
    Write-Host "  ✓ Added Cloudflare DNS (1.1.1.1)" -ForegroundColor Green
}
Write-Host "  ✓ DNS forwarders configured" -ForegroundColor Green

# Step 4: Install and Configure DHCP
Write-Host "`n[4/7] Installing and configuring DHCP..." -ForegroundColor Yellow
if ((Get-WindowsFeature -Name DHCP).InstallState -ne "Installed") {
    Install-WindowsFeature -Name DHCP -IncludeManagementTools
    Write-Host "  ✓ DHCP installed" -ForegroundColor Green
}

# Authorize DHCP in AD
try {
    Add-DhcpServerInDC -DnsName "DC01.$($Config.DomainName)" -IPAddress $Config.DNSServer
    Write-Host "  ✓ DHCP authorized in Active Directory" -ForegroundColor Green
} catch {
    Write-Host "  ℹ DHCP already authorized or authorization not needed" -ForegroundColor Cyan
}

# Create DHCP scope
if (-not (Get-DhcpServerv4Scope -ScopeId $Config.DHCPSubnet -ErrorAction SilentlyContinue)) {
    Add-DhcpServerv4Scope `
        -Name "Lab Network" `
        -StartRange $Config.DHCPScopeStart `
        -EndRange $Config.DHCPScopeEnd `
        -SubnetMask $Config.DHCPSubnetMask `
        -State Active
    
    Set-DhcpServerv4OptionValue `
        -ScopeId $Config.DHCPSubnet `
        -DnsServer $Config.DNSServer `
        -Router $Config.Gateway
    
    Write-Host "  ✓ DHCP scope created: $($Config.DHCPScopeStart) - $($Config.DHCPScopeEnd)" -ForegroundColor Green
} else {
    Write-Host "  ✓ DHCP scope already exists" -ForegroundColor Green
}

Restart-Service DHCPServer -ErrorAction SilentlyContinue
Write-Host "  ✓ DHCP service restarted" -ForegroundColor Green

# Step 5: Create OU Structure
Write-Host "`n[5/7] Creating Organizational Unit structure..." -ForegroundColor Yellow
$OUs = @("LabUsers", "LabComputers", "LabServers", "LabGroups")
$DomainDN = "DC=" + ($Config.DomainName -replace "\.", ",DC=")

foreach ($OU in $OUs) {
    $OUPath = "OU=$OU,$DomainDN"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OUPath'" -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $OU -Path $DomainDN
        Write-Host "  ✓ Created OU: $OU" -ForegroundColor Green
    } else {
        Write-Host "  ✓ OU already exists: $OU" -ForegroundColor Green
    }
}

# Step 6: Create Security Groups
Write-Host "`n[6/7] Creating security groups..." -ForegroundColor Yellow
$Groups = @("IT-Admins", "HR-Team", "Finance-Team", "Sales-Team", "Domain-Admins-Lab")
$GroupsPath = "OU=LabGroups,$DomainDN"

foreach ($Group in $Groups) {
    if (-not (Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction SilentlyContinue)) {
        New-ADGroup `
            -Name $Group `
            -GroupScope Global `
            -GroupCategory Security `
            -Path $GroupsPath `
            -Description "Lab group for $Group"
        Write-Host "  ✓ Created group: $Group" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Group already exists: $Group" -ForegroundColor Green
    }
}

# Step 7: Create Test Users
Write-Host "`n[7/7] Creating test user accounts..." -ForegroundColor Yellow
$Users = @(
    @{FirstName="John"; LastName="Doe"; Username="jdoe"; Department="IT"; Title="System Administrator"},
    @{FirstName="Jane"; LastName="Smith"; Username="jsmith"; Department="HR"; Title="HR Manager"},
    @{FirstName="Bob"; LastName="Johnson"; Username="bjohnson"; Department="Finance"; Title="Financial Analyst"},
    @{FirstName="Alice"; LastName="Williams"; Username="awilliams"; Department="Sales"; Title="Sales Representative"},
    @{FirstName="Admin"; LastName="User"; Username="labadmin"; Department="IT"; Title="Domain Administrator"}
)

$UsersPath = "OU=LabUsers,$DomainDN"
$DefaultPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

foreach ($User in $Users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($User.Username)'" -ErrorAction SilentlyContinue)) {
        New-ADUser `
            -Name "$($User.FirstName) $($User.LastName)" `
            -GivenName $User.FirstName `
            -Surname $User.LastName `
            -SamAccountName $User.Username `
            -UserPrincipalName "$($User.Username)@$($Config.DomainName)" `
            -Path $UsersPath `
            -AccountPassword $DefaultPassword `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -Department $User.Department `
            -Title $User.Title `
            -Description "Test user account for $($User.Department)"
        Write-Host "  ✓ Created user: $($User.Username) ($($User.FirstName) $($User.LastName))" -ForegroundColor Green
    } else {
        Write-Host "  ✓ User already exists: $($User.Username)" -ForegroundColor Green
    }
}

# Add users to groups
Add-ADGroupMember -Identity "Domain Admins" -Members "labadmin" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "IT-Admins" -Members "jdoe", "labadmin" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "HR-Team" -Members "jsmith" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "Finance-Team" -Members "bjohnson" -ErrorAction SilentlyContinue
Add-ADGroupMember -Identity "Sales-Team" -Members "awilliams" -ErrorAction SilentlyContinue

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Configuration Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

# Display summary
Write-Host "Domain Information:" -ForegroundColor Yellow
Write-Host "  Domain Name: $($Config.DomainName)" -ForegroundColor White
Write-Host "  NetBIOS Name: $($Config.DomainNetBIOS)" -ForegroundColor White
Write-Host "  DNS Server: $($Config.DNSServer)" -ForegroundColor White
Write-Host "  DHCP Range: $($Config.DHCPScopeStart) - $($Config.DHCPScopeEnd)" -ForegroundColor White

Write-Host "`nTest User Credentials:" -ForegroundColor Yellow
Write-Host "  Username: HOMELAB\jdoe" -ForegroundColor White
Write-Host "  Password: P@ssw0rd123! (must change at first login)" -ForegroundColor White
Write-Host "  Admin User: HOMELAB\labadmin" -ForegroundColor White

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Join member servers to the domain (FS01)" -ForegroundColor White
Write-Host "  2. Join client workstations to the domain (CLIENT1)" -ForegroundColor White
Write-Host "  3. Configure Group Policies" -ForegroundColor White
Write-Host "  4. Setup Azure AD Connect for M365 integration`n" -ForegroundColor White

Write-Host "Verification Commands:" -ForegroundColor Yellow
Write-Host "  Get-ADDomain" -ForegroundColor Cyan
Write-Host "  Get-ADUser -Filter * | Select Name, SamAccountName" -ForegroundColor Cyan
Write-Host "  Get-DhcpServerv4Scope" -ForegroundColor Cyan
Write-Host "  Get-ADOrganizationalUnit -Filter *`n" -ForegroundColor Cyan