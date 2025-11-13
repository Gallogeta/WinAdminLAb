# IT Support Desk - Complete Training Guide

## Overview

This guide covers essential IT Support Desk skills for Windows, Active Directory, Microsoft 365, and Outlook administration. Perfect for Help Desk roles, IT Support positions, and System Administration.

## Table of Contents

1. [User Account Management](#user-account-management)
2. [Password Management](#password-management)
3. [Account Lockouts](#account-lockouts)
4. [Group Membership](#group-membership)
5. [File Share Permissions](#file-share-permissions)
6. [Windows Troubleshooting](#windows-troubleshooting)
7. [Microsoft 365 Administration](#microsoft-365-administration)
8. [Outlook Issues](#outlook-issues)
9. [Common Support Tickets](#common-support-tickets)

---

## User Account Management

### Creating New User Accounts

**Scenario:** New employee John Smith joins the IT department.

#### PowerShell Method (Recommended):

```powershell
# Create new AD user
New-ADUser `
    -Name "John Smith" `
    -GivenName "John" `
    -Surname "Smith" `
    -SamAccountName "jsmith" `
    -UserPrincipalName "jsmith@homelab.local" `
    -Path "OU=LabUsers,DC=homelab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "TempPass123!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "IT" `
    -Title "IT Support Specialist" `
    -EmailAddress "jsmith@yourdomain.com" `
    -OfficePhone "555-1234"

# Verify user creation
Get-ADUser jsmith -Properties *
```

#### GUI Method:

1. Open **Active Directory Users and Computers** (dsa.msc)
2. Navigate to **LabUsers** OU
3. Right-click → **New** → **User**
4. Fill in details:
   - First name: John
   - Last name: Smith
   - User logon name: jsmith
5. Click **Next**
6. Set password
7. Check **"User must change password at next logon"**
8. Click **Next** → **Finish**

### Modifying User Accounts

```powershell
# Change user's department
Set-ADUser jsmith -Department "Sales"

# Update phone number
Set-ADUser jsmith -OfficePhone "555-5678"

# Change email address
Set-ADUser jsmith -EmailAddress "john.smith@company.com"

# Update job title
Set-ADUser jsmith -Title "Senior IT Support"

# Set manager
Set-ADUser jsmith -Manager "bjohnson"

# Add description
Set-ADUser jsmith -Description "IT Support - Phoenix Office"
```

### Disabling User Accounts

**When to disable:**
- Employee on extended leave
- Pending termination investigation
- Security incident

```powershell
# Disable user account
Disable-ADAccount -Identity jsmith

# Verify
Get-ADUser jsmith | Select-Object Name, Enabled

# Move to disabled OU
Move-ADObject -Identity (Get-ADUser jsmith).DistinguishedName -TargetPath "OU=Disabled,DC=homelab,DC=local"
```

### Deleting User Accounts

**Best Practice:** Disable first, delete after 30-90 days.

```powershell
# Remove user account (CAREFUL!)
Remove-ADUser -Identity jsmith -Confirm

# Better: Disable and document
Disable-ADAccount -Identity jsmith
Set-ADUser jsmith -Description "DISABLED: Terminated $(Get-Date -Format 'yyyy-MM-dd')"
```

---

## Password Management

### Common Password Issues

#### User Forgot Password

```powershell
# Reset password (force change at logon)
Set-ADAccountPassword -Identity jsmith -Reset -NewPassword (ConvertTo-SecureString "NewTemp123!" -AsPlainText -Force)
Set-ADUser jsmith -ChangePasswordAtLogon $true

# Verify
Get-ADUser jsmith -Properties PasswordLastSet, PasswordExpired
```

#### Password Expiration

```powershell
# Check password expiration
Get-ADUser jsmith -Properties PasswordLastSet, PasswordNeverExpires, PasswordExpired

# Set password to never expire (service accounts)
Set-ADUser jsmith -PasswordNeverExpires $true

# Check when password expires
Get-ADUser jsmith -Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
Select-Object -Property "DisplayName", @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}
```

#### Bulk Password Reset

```powershell
# Reset passwords for multiple users
$Users = @("jsmith", "bjohnson", "awilliams")
$NewPassword = "TempPass123!"

foreach ($User in $Users) {
    Set-ADAccountPassword -Identity $User -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
    Set-ADUser $User -ChangePasswordAtLogon $true
    Write-Host "Password reset for $User" -ForegroundColor Green
}
```

#### Password Policy Check

```powershell
# View default domain password policy
Get-ADDefaultDomainPasswordPolicy

# Common settings:
# - MinPasswordLength: 7
# - PasswordHistoryCount: 24
# - MaxPasswordAge: 42 days
# - LockoutThreshold: 5 attempts
# - LockoutDuration: 30 minutes
```

---

## Account Lockouts

### Diagnosing Lockouts

**Common Causes:**
- User typing wrong password multiple times
- Saved credentials in applications (Outlook, mapped drives)
- Mobile device with old password
- Scheduled tasks running with old credentials
- Browser auto-fill with old password

#### Check if Account is Locked

```powershell
# Check lockout status
Get-ADUser jsmith -Properties LockedOut, LockoutTime, LastBadPasswordAttempt |
Select-Object Name, LockedOut, LockoutTime, LastBadPasswordAttempt

# Check all locked accounts
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LockedOut
```

#### Unlock Account

```powershell
# Unlock user account
Unlock-ADAccount -Identity jsmith

# Verify
Get-ADUser jsmith -Properties LockedOut | Select-Object Name, LockedOut
```

#### Find Lockout Source

```powershell
# Check security event logs on DC for lockouts
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 50 |
Where-Object {$_.Properties[0].Value -eq 'jsmith'} |
Format-Table TimeCreated, @{Name="Username";Expression={$_.Properties[0].Value}}, @{Name="SourceComputer";Expression={$_.Properties[1].Value}}
```

#### Prevent Future Lockouts

**Support Desk Checklist:**
1. Unlock the account
2. Ask user to clear saved credentials:
   - Windows: Control Panel → Credential Manager
   - Remove all saved credentials for company domain
3. Check mobile devices (remove and re-add email account)
4. Check browser saved passwords
5. Update any mapped drives or shortcuts
6. Restart computer

---

## Group Membership

### Adding Users to Groups

```powershell
# Add user to security group
Add-ADGroupMember -Identity "IT-Admins" -Members jsmith

# Add multiple users
Add-ADGroupMember -Identity "IT-Admins" -Members jsmith, bjohnson, awilliams

# Verify membership
Get-ADGroupMember -Identity "IT-Admins" | Select-Object Name, SamAccountName
```

### Removing Users from Groups

```powershell
# Remove user from group
Remove-ADGroupMember -Identity "IT-Admins" -Members jsmith -Confirm:$false

# Verify
Get-ADGroupMember -Identity "IT-Admins"
```

### Check User's Group Memberships

```powershell
# List all groups user belongs to
Get-ADUser jsmith -Properties MemberOf | Select-Object -ExpandProperty MemberOf

# Better formatted
Get-ADPrincipalGroupMembership jsmith | Select-Object Name, GroupScope
```

### Copy Group Memberships

**Scenario:** New user should have same access as existing user.

```powershell
# Copy group memberships from one user to another
$SourceUser = "jdoe"
$TargetUser = "jsmith"

$Groups = Get-ADPrincipalGroupMembership $SourceUser | Where-Object {$_.Name -ne "Domain Users"}

foreach ($Group in $Groups) {
    Add-ADGroupMember -Identity $Group -Members $TargetUser
    Write-Host "Added $TargetUser to $($Group.Name)" -ForegroundColor Green
}
```

---

## File Share Permissions

### Common Permission Issues

#### User Can't Access Share

**Troubleshooting Steps:**

```powershell
# 1. Check if user is in correct group
Get-ADPrincipalGroupMembership jsmith | Select-Object Name

# 2. Check share permissions
Get-SmbShareAccess -Name "IT"

# 3. Check NTFS permissions
Get-Acl "C:\Shares\IT" | Format-List

# 4. Test path accessibility
Test-Path "\\FS01\IT"
```

#### Grant User Access to Share

```powershell
# Add user to appropriate group
Add-ADGroupMember -Identity "IT-Admins" -Members jsmith

# Or grant direct share permission (not recommended)
Grant-SmbShareAccess -Name "IT" -AccountName "HOMELAB\jsmith" -AccessRight Full -Force
```

#### Map Network Drive for User

**Via PowerShell:**
```powershell
# Map drive
New-PSDrive -Name "Z" -PSProvider FileSystem -Root "\\FS01\IT" -Persist

# Via Group Policy is better - create logon script
```

**Via GUI:**
1. Open File Explorer
2. Right-click **This PC** → **Map network drive**
3. Drive: Z:
4. Folder: `\\FS01\IT`
5. Check **"Reconnect at sign-in"**
6. Click **Finish**

### Check Effective Permissions

```powershell
# View effective NTFS permissions
$Path = "C:\Shares\IT"
$User = "HOMELAB\jsmith"

(Get-Acl $Path).Access | Where-Object {$_.IdentityReference -eq $User}
```

---

## Windows Troubleshooting

### Computer Can't Connect to Domain

**Symptoms:** User can't login, "No logon servers available"

```powershell
# Check domain connectivity
Test-ComputerSecureChannel -Verbose

# Repair trust relationship
Test-ComputerSecureChannel -Repair -Credential (Get-Credential HOMELAB\Administrator)

# Check DNS settings
Get-DnsClientServerAddress

# Set correct DNS
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.91")
```

### Profile Issues

**Symptoms:** Slow login, "temporary profile"

```powershell
# Check user profile path
Get-ADUser jsmith -Properties ProfilePath | Select-Object Name, ProfilePath

# Delete local profile (user must be logged out)
Get-CimInstance -ClassName Win32_UserProfile | 
Where-Object {$_.LocalPath -like "*jsmith*"} | 
Remove-CimInstance

# User will get fresh profile on next login
```

### Cannot Access Network Resources

```powershell
# Clear cached credentials
cmdkey /list
cmdkey /delete:FS01

# Restart workstation service
Restart-Service Workstation

# Check network discovery
Get-NetConnectionProfile
Set-NetConnectionProfile -NetworkCategory Private

# Enable network discovery
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
```

---

## Microsoft 365 Administration

### User Licensing

```powershell
# Connect to M365
Connect-MsolService

# View available licenses
Get-MsolAccountSku

# Assign license to user
Set-MsolUser -UserPrincipalName jsmith@yourdomain.com -UsageLocation "US"
Set-MsolUserLicense -UserPrincipalName jsmith@yourdomain.com -AddLicenses "company:ENTERPRISEPACK"

# Remove license
Set-MsolUserLicense -UserPrincipalName jsmith@yourdomain.com -RemoveLicenses "company:ENTERPRISEPACK"

# Check user's licenses
Get-MsolUser -UserPrincipalName jsmith@yourdomain.com | Select-Object DisplayName, Licenses
```

### Distribution Lists

```powershell
# Create distribution group
New-DistributionGroup -Name "IT Team" -Alias "ITTeam" -Members jsmith, bjohnson

# Add members
Add-DistributionGroupMember -Identity "IT Team" -Member awilliams

# Remove members
Remove-DistributionGroupMember -Identity "IT Team" -Member awilliams

# List members
Get-DistributionGroupMember -Identity "IT Team"
```

### Shared Mailboxes

```powershell
# Create shared mailbox
New-Mailbox -Shared -Name "IT Support" -DisplayName "IT Support" -Alias itsupport

# Grant access
Add-MailboxPermission -Identity "IT Support" -User jsmith -AccessRights FullAccess -InheritanceType All

# Grant Send As permission
Add-RecipientPermission -Identity "IT Support" -Trustee jsmith -AccessRights SendAs

# Check permissions
Get-MailboxPermission -Identity "IT Support" | Where-Object {$_.User -like "*jsmith*"}
```

---

## Outlook Issues

### Cannot Connect to Exchange

**Troubleshooting Steps:**

1. **Check credentials:**
   - File → Account Settings → Account Settings
   - Verify email address and password

2. **Test autodiscover:**
   ```powershell
   Test-OutlookConnectivity -Protocol Autodiscover -MailboxId jsmith@company.com
   ```

3. **Rebuild Outlook profile:**
   - Control Panel → Mail → Show Profiles
   - Add new profile
   - Set as default

### Mailbox Full

```powershell
# Check mailbox size
Get-MailboxStatistics -Identity jsmith | Select-Object DisplayName, TotalItemSize, ItemCount

# Check mailbox quota
Get-Mailbox -Identity jsmith | Select-Object DisplayName, ProhibitSendQuota, ProhibitSendReceiveQuota

# Increase quota
Set-Mailbox -Identity jsmith -ProhibitSendReceiveQuota 50GB -ProhibitSendQuota 49GB -IssueWarningQuota 48GB
```

### Calendar Permissions

```powershell
# Grant calendar access
Add-MailboxFolderPermission -Identity "jsmith:\Calendar" -User bjohnson -AccessRights Editor

# Remove calendar access
Remove-MailboxFolderPermission -Identity "jsmith:\Calendar" -User bjohnson

# Check calendar permissions
Get-MailboxFolderPermission -Identity "jsmith:\Calendar"
```

### Outlook Search Not Working

**Fix Steps:**
1. Close Outlook
2. Control Panel → Indexing Options
3. Modify → Check Outlook
4. Rebuild index
5. Restart Outlook

**PowerShell:**
```powershell
# Rebuild Outlook search index
outlook.exe /cleanfinders
outlook.exe /resetnavpane
```

### Out of Office

```powershell
# Set automatic replies
Set-MailboxAutoReplyConfiguration -Identity jsmith `
    -AutoReplyState Enabled `
    -InternalMessage "I am out of office until Monday." `
    -ExternalMessage "I am currently out of office."

# Check auto-reply status
Get-MailboxAutoReplyConfiguration -Identity jsmith

# Disable auto-reply
Set-MailboxAutoReplyConfiguration -Identity jsmith -AutoReplyState Disabled
```

---

## Common Support Tickets

### Ticket 1: New Employee Setup

**Task:** Create account for new employee Sarah Johnson, Sales department.

```powershell
# 1. Create AD account
New-ADUser `
    -Name "Sarah Johnson" `
    -SamAccountName "sjohnson" `
    -UserPrincipalName "sjohnson@homelab.local" `
    -Path "OU=LabUsers,DC=homelab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "Sales"

# 2. Add to groups
Add-ADGroupMember -Identity "Sales-Team" -Members sjohnson

# 3. Grant file share access (automatically via group)
# 4. Assign M365 license
Set-MsolUser -UserPrincipalName sjohnson@company.com -UsageLocation "US"
Set-MsolUserLicense -UserPrincipalName sjohnson@company.com -AddLicenses "company:ENTERPRISEPACK"

# 5. Verify
Get-ADUser sjohnson -Properties MemberOf
```

### Ticket 2: User Locked Out

**Task:** John Smith (jsmith) is locked out after vacation.

```powershell
# 1. Check lockout status
Get-ADUser jsmith -Properties LockedOut, LastBadPasswordAttempt

# 2. Unlock account
Unlock-ADAccount -Identity jsmith

# 3. Reset password if needed
Set-ADAccountPassword -Identity jsmith -Reset -NewPassword (ConvertTo-SecureString "NewTemp123!" -AsPlainText -Force)
Set-ADUser jsmith -ChangePasswordAtLogon $true

# 4. Inform user to clear saved credentials on phone
```

### Ticket 3: Can't Access Shared Drive

**Task:** User can't access \\FS01\IT share.

```powershell
# 1. Check group membership
Get-ADPrincipalGroupMembership jsmith | Where-Object {$_.Name -like "*IT*"}

# 2. Add to correct group if missing
Add-ADGroupMember -Identity "IT-Admins" -Members jsmith

# 3. Verify share permissions
Get-SmbShareAccess -Name "IT"

# 4. Test from user's computer
Test-Path "\\FS01\IT"

# 5. User may need to log out/in for group changes to take effect
```

### Ticket 4: Mailbox Full

**Task:** User receiving bounce-backs, mailbox full.

```powershell
# 1. Check mailbox size
Get-MailboxStatistics jsmith | Select-Object TotalItemSize, ItemCount

# 2. Check quota
Get-Mailbox jsmith | Select-Object ProhibitSendReceiveQuota

# 3. Options:
#    a) Increase quota (if policy allows)
Set-Mailbox jsmith -ProhibitSendReceiveQuota 50GB

#    b) Have user archive or delete emails
#    c) Enable online archive
Enable-Mailbox jsmith -Archive
```

### Ticket 5: Cannot Log Into Computer

**Task:** "No logon servers available" error.

```powershell
# 1. Check if computer account is disabled
Get-ADComputer CLIENT1 | Select-Object Name, Enabled

# 2. Test domain trust
# (Run on CLIENT1)
Test-ComputerSecureChannel -Verbose

# 3. Repair if broken
Test-ComputerSecureChannel -Repair -Credential (Get-Credential HOMELAB\Administrator)

# 4. Check DNS
Get-DnsClientServerAddress

# 5. Set DNS to DC
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.91")
```

---

## Practice Exercises

### Exercise 1: User Onboarding

Create complete setup for new user:
1. Create AD account
2. Add to appropriate groups
3. Set up email
4. Configure file share access
5. Document all steps

### Exercise 2: Troubleshooting Lockout

Simulate and resolve account lockout:
1. Lock account by entering wrong password 5 times
2. Identify lockout in logs
3. Unlock account
4. Identify source of lockout
5. Prevent future occurrences

### Exercise 3: Permission Audit

Audit and fix file share permissions:
1. List all users with access to IT share
2. Remove users who shouldn't have access
3. Add users who need access
4. Document findings

### Exercise 4: Outlook Configuration

Set up Outlook for new user:
1. Create mailbox
2. Configure Outlook profile
3. Set up calendar sharing
4. Configure out-of-office
5. Test send/receive

---

## Quick Reference Commands

```powershell
# User Management
Get-ADUser username
Set-ADUser username -Property value
Disable-ADAccount username
Unlock-ADAccount username

# Password Management
Set-ADAccountPassword username -Reset
Set-ADUser username -ChangePasswordAtLogon $true

# Group Management
Add-ADGroupMember "GroupName" -Members username
Get-ADGroupMember "GroupName"

# M365
Connect-MsolService
Get-MsolUser -UserPrincipalName user@domain.com
Set-MsolUserLicense -UserPrincipalName user@domain.com -AddLicenses "license:SKU"

# Exchange
Get-Mailbox username
Set-Mailbox username -ProhibitSendReceiveQuota 50GB
Add-MailboxPermission -Identity mailbox -User user -AccessRights FullAccess
```

---

## Additional Resources

- Microsoft Learn: https://learn.microsoft.com
- Active Directory Best Practices
- M365 Admin Center: https://admin.microsoft.com
- Support ticket templates and documentation

This guide covers 90% of common Help Desk tickets!
