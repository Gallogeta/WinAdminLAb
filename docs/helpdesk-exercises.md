# Help Desk Lab Exercises

## Overview

Practical hands-on exercises simulating real Help Desk scenarios. Complete these in order to build your skills.

---

## Exercise 1: New User Onboarding

**Difficulty:** Beginner  
**Time:** 20 minutes  
**Scenario:** New employee joining the company

### Background
Sarah Williams starts Monday in the HR department. She needs:
- Active Directory account
- Email access
- HR shared folder access
- Standard company software

### Your Tasks

1. **Create AD Account**
   - Username: swilliams
   - Full name: Sarah Williams
   - Department: HR
   - Initial password: Welcome2024!
   - Must change password at first logon

2. **Configure Group Membership**
   - Add to: HR-Team
   - Add to: All-Employees (if exists)

3. **Verify File Share Access**
   - Confirm she can access \\FS01\HR
   - Cannot access \\FS01\IT or \\FS01\Finance

4. **Documentation**
   - Username and temporary password
   - Groups assigned
   - Resources accessible

### Solution

```powershell
# 1. Create user
New-ADUser `
    -Name "Sarah Williams" `
    -GivenName "Sarah" `
    -Surname "Williams" `
    -SamAccountName "swilliams" `
    -UserPrincipalName "swilliams@homelab.local" `
    -Path "OU=LabUsers,DC=homelab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force) `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "HR" `
    -Description "HR Department - Created $(Get-Date -Format 'yyyy-MM-dd')"

# 2. Add to groups
Add-ADGroupMember -Identity "HR-Team" -Members swilliams

# 3. Verify
Get-ADUser swilliams -Properties MemberOf | Select-Object Name, MemberOf
Get-SmbShareAccess -Name "HR"

# 4. Test from CLIENT1 as swilliams
Test-Path "\\FS01\HR"
```

### Success Criteria
- [ ] User can log into CLIENT1
- [ ] User forced to change password
- [ ] User can access \\FS01\HR
- [ ] User cannot access \\FS01\IT

---

## Exercise 2: Password Reset & Account Unlock

**Difficulty:** Beginner  
**Time:** 15 minutes  
**Scenario:** User forgot password and account is locked

### Background
John Doe (jdoe) called saying he can't log in. He tried his password multiple times and now gets "account locked" message.

### Your Tasks

1. **Diagnose the Issue**
   - Check if account is locked
   - Check when lockout occurred
   - Check last bad password attempt

2. **Resolve**
   - Unlock the account
   - Reset password to TempReset123!
   - Require password change at next logon

3. **Prevent Recurrence**
   - Advise user to check saved credentials
   - Check for mobile device issues
   - Document the incident

### Solution

```powershell
# 1. Check lockout status
Get-ADUser jdoe -Properties LockedOut, LockoutTime, LastBadPasswordAttempt, BadPwdCount |
Select-Object Name, LockedOut, LockoutTime, LastBadPasswordAttempt, BadPwdCount

# 2. Unlock account
Unlock-ADAccount -Identity jdoe

# 3. Reset password
Set-ADAccountPassword -Identity jdoe -Reset -NewPassword (ConvertTo-SecureString "TempReset123!" -AsPlainText -Force)
Set-ADUser jdoe -ChangePasswordAtLogon $true

# 4. Verify
Get-ADUser jdoe -Properties LockedOut, PasswordLastSet | 
Select-Object Name, Enabled, LockedOut, PasswordLastSet

# 5. Check lockout source in event logs (on DC01)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4740} -MaxEvents 10 |
Where-Object {$_.Properties[0].Value -eq 'jdoe'} |
Format-Table TimeCreated, @{Name="Computer";Expression={$_.Properties[1].Value}}
```

### User Checklist to Provide
- Clear saved credentials in Windows
- Check phone/tablet email setup
- Check browser saved passwords
- Restart computer after changing password

### Success Criteria
- [ ] Account unlocked
- [ ] Password reset
- [ ] User can log in
- [ ] Source of lockout identified
- [ ] Incident documented

---

## Exercise 3: File Share Permission Issues

**Difficulty:** Intermediate  
**Time:** 25 minutes  
**Scenario:** User can't access department folder

### Background
Bob Johnson (bjohnson) was transferred from Finance to IT. He can still access Finance folder but needs access to IT folder.

### Your Tasks

1. **Audit Current Access**
   - What groups is bjohnson in?
   - What shares can he access?

2. **Update Permissions**
   - Add to IT-Admins group
   - Remove from Finance-Team group
   - Update AD attributes (Department)

3. **Verify Access**
   - Can access \\FS01\IT
   - Cannot access \\FS01\Finance

4. **Document Changes**
   - What changed
   - Why changed
   - When changed

### Solution

```powershell
# 1. Check current groups
Get-ADPrincipalGroupMembership bjohnson | Select-Object Name

# 2. Check current department
Get-ADUser bjohnson -Properties Department | Select-Object Name, Department

# 3. Update groups
Add-ADGroupMember -Identity "IT-Admins" -Members bjohnson
Remove-ADGroupMember -Identity "Finance-Team" -Members bjohnson -Confirm:$false

# 4. Update department
Set-ADUser bjohnson -Department "IT"

# 5. Verify changes
Get-ADUser bjohnson -Properties Department, MemberOf |
Select-Object Name, Department, @{Name="Groups";Expression={$_.MemberOf}}

# 6. Test share access (from CLIENT1 as bjohnson)
# User must log out and back in for group changes to take effect
Test-Path "\\FS01\IT"
Test-Path "\\FS01\Finance"

# 7. Check share permissions
Get-SmbShareAccess -Name "IT"
Get-SmbShareAccess -Name "Finance"
```

### Important Notes
- Group membership changes require logout/login
- Or use `klist purge` and re-authenticate
- Document all permission changes

### Success Criteria
- [ ] User in correct groups
- [ ] AD Department updated
- [ ] Can access IT share
- [ ] Cannot access Finance share
- [ ] Changes documented

---

## Exercise 4: Computer Can't Connect to Domain

**Difficulty:** Intermediate  
**Time:** 30 minutes  
**Scenario:** Workstation won't let user log in

### Background
CLIENT1 displays error: "The trust relationship between this workstation and the primary domain failed."

### Your Tasks

1. **Diagnose**
   - Is computer online?
   - Can it ping DC?
   - Is DNS configured correctly?
   - Is computer account active in AD?

2. **Test Trust Relationship**
   - Run trust relationship test
   - Check if repairs needed

3. **Fix**
   - Repair trust or rejoin domain
   - Verify DNS settings

4. **Test**
   - User can log in
   - Domain resources accessible

### Solution

```powershell
# On CLIENT1 (PowerShell as Administrator)

# 1. Check network connectivity
Test-Connection DC01.homelab.local
ping 192.168.0.91

# 2. Check DNS
Get-DnsClientServerAddress

# 3. Fix DNS if needed
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses ("192.168.0.91")

# 4. Test domain trust
Test-ComputerSecureChannel -Verbose

# 5. If failed, repair trust
Test-ComputerSecureChannel -Repair -Credential (Get-Credential HOMELAB\Administrator)

# 6. If repair fails, check on DC01 if computer account exists
# On DC01:
Get-ADComputer CLIENT1

# 7. If doesn't exist or repair fails, rejoin domain
# Remove from domain first (on CLIENT1)
Remove-Computer -Credential (Get-Credential HOMELAB\Administrator) -PassThru -Verbose -Force -Restart

# After restart, rejoin
Add-Computer -DomainName "homelab.local" -Credential (Get-Credential HOMELAB\Administrator) -Restart

# 8. Verify (after restart)
Test-ComputerSecureChannel -Verbose
Get-ADComputer CLIENT1 -Server DC01
```

### Troubleshooting Steps
1. Check network cable/WiFi
2. Verify DNS points to DC
3. Ping domain controller
4. Test trust relationship
5. Check computer account in AD
6. Repair or rejoin domain

### Success Criteria
- [ ] Computer can communicate with DC
- [ ] DNS configured correctly
- [ ] Trust relationship restored
- [ ] User can log in
- [ ] Network resources accessible

---

## Exercise 5: Group Policy Not Applying

**Difficulty:** Intermediate  
**Time:** 20 minutes  
**Scenario:** User reports desktop wallpaper policy not working

### Background
You created a GPO to set company wallpaper, but it's not applying to CLIENT1.

### Your Tasks

1. **Check GPO Link**
   - Is GPO linked to correct OU?
   - Is it enabled?

2. **Force Update**
   - Run gpupdate on CLIENT1

3. **Verify Application**
   - Check which policies applied
   - Check for errors

4. **Troubleshoot**
   - Check event logs
   - Run GP results

### Solution

```powershell
# On CLIENT1

# 1. Force Group Policy update
gpupdate /force

# 2. Check which policies are applied
gpresult /r

# 3. Generate detailed report
gpresult /h C:\gpreport.html
Start-Process C:\gpreport.html

# 4. Check for policy errors
Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 50 |
Where-Object {$_.LevelDisplayName -eq "Error"} |
Format-Table TimeCreated, Message -Wrap

# On DC01 - Check GPO settings
Import-Module GroupPolicy

# List all GPOs
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime

# Check where GPO is linked
Get-GPO -Name "Company Policies" | Get-GPInheritance

# Check if computer is in correct OU
Get-ADComputer CLIENT1 | Select-Object DistinguishedName
```

### Common Issues
- Computer not in correct OU
- GPO not linked or disabled
- Loopback processing needed
- Policy hasn't replicated
- User in Deny list

### Success Criteria
- [ ] GPO linked to correct OU
- [ ] Policy applied successfully
- [ ] No errors in logs
- [ ] Setting visible on client

---

## Exercise 6: User Profile Corruption

**Difficulty:** Advanced  
**Time:** 30 minutes  
**Scenario:** User getting "temporary profile" error

### Background
Jane Smith (jsmith) logs in but gets "You've been signed in with a temporary profile." All her files and settings are missing.

### Your Tasks

1. **Diagnose**
   - Check local profile status
   - Check profile path in AD
   - Check for .bak profile

2. **Fix**
   - Delete corrupted local profile
   - User will get fresh profile on next login

3. **Recover Data** (if possible)
   - Copy important files from old profile
   - Restore if using roaming profiles

### Solution

```powershell
# On CLIENT1 (jsmith must be logged out)

# 1. Check local profiles
Get-CimInstance -ClassName Win32_UserProfile | 
Select-Object LocalPath, Loaded, Special |
Format-Table -AutoSize

# 2. Find jsmith's profile
$Profile = Get-CimInstance -ClassName Win32_UserProfile |
Where-Object {$_.LocalPath -like "*jsmith*"}

$Profile | Format-List

# 3. Back up important data FIRST
$BackupPath = "C:\ProfileBackup\jsmith_$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path $BackupPath -ItemType Directory
Copy-Item -Path "C:\Users\jsmith\Documents\*" -Destination $BackupPath -Recurse -ErrorAction SilentlyContinue
Copy-Item -Path "C:\Users\jsmith\Desktop\*" -Destination $BackupPath -Recurse -ErrorAction SilentlyContinue

# 4. Delete corrupted profile
$Profile | Remove-CimInstance

# 5. Check registry for leftover entries
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
# Manually delete if needed

# 6. User logs in - gets fresh profile

# 7. Restore backed up files
# Copy from C:\ProfileBackup\jsmith_YYYYMMDD back to user's new profile
```

### On DC01 - Check Roaming Profile Settings

```powershell
# Check if roaming profile is configured
Get-ADUser jsmith -Properties ProfilePath | Select-Object Name, ProfilePath

# If using roaming profiles and path is incorrect
Set-ADUser jsmith -ProfilePath "\\DC01\Profiles$\jsmith"
```

### Prevention
- Enable roaming profiles
- Regular profile backups
- User education on saving to network drives

### Success Criteria
- [ ] Corrupted profile deleted
- [ ] User data backed up
- [ ] New profile created on login
- [ ] User can access settings
- [ ] Important files restored

---

## Exercise 7: Outlook Not Connecting

**Difficulty:** Intermediate  
**Time:** 25 minutes  
**Scenario:** Outlook won't connect to mailbox

### Background
User reports Outlook keeps asking for password and won't connect.

### Your Tasks

1. **Diagnose**
   - Test credentials
   - Check Outlook profile
   - Test autodiscover

2. **Fix**
   - Recreate Outlook profile
   - Update credentials
   - Test connectivity

### Solution

```powershell
# 1. Test user credentials in AD
Get-ADUser jsmith | Select-Object Name, Enabled, LockedOut

# 2. Check mailbox exists (if M365)
Get-Mailbox jsmith

# On CLIENT1

# 3. Test Outlook connectivity
outlook.exe /safe

# 4. Clear cached credentials
Control Panel → Credential Manager → Windows Credentials
# Remove all Outlook/Office credentials

# 5. Recreate Outlook profile
Control Panel → Mail (Microsoft Outlook) → Show Profiles → Add

# 6. Test autodiscover (if Exchange)
# Hold Ctrl, right-click Outlook tray icon
# Test Email Auto-Configuration

# 7. Reset Outlook
outlook.exe /resetnavpane
outlook.exe /cleanprofile

# 8. Repair Office installation
# Control Panel → Programs → Microsoft Office → Change → Repair
```

### Common Issues
- Wrong password
- Account locked
- Cached credentials
- Corrupted Outlook profile
- Network/firewall issues
- Expired license

### Success Criteria
- [ ] Credentials verified
- [ ] Outlook profile recreated
- [ ] Connection successful
- [ ] Can send/receive email

---

## Exercise 8: Shared Mailbox Access

**Difficulty:** Intermediate  
**Time:** 20 minutes  
**Scenario:** User needs access to shared mailbox

### Background
IT Support shared mailbox (itsupport@company.com) needs to be accessible by Bob Johnson and Jane Smith.

### Your Tasks

1. **Create Shared Mailbox** (if doesn't exist)
2. **Grant Full Access** to both users
3. **Grant Send As** permission
4. **Configure in Outlook**

### Solution

```powershell
# Connect to Exchange Online (if M365)
Connect-ExchangeOnline

# 1. Create shared mailbox
New-Mailbox -Shared -Name "IT Support" -DisplayName "IT Support" -Alias "itsupport" -PrimarySmtpAddress "itsupport@company.com"

# 2. Grant Full Access
Add-MailboxPermission -Identity "itsupport@company.com" -User "bjohnson@company.com" -AccessRights FullAccess -InheritanceType All
Add-MailboxPermission -Identity "itsupport@company.com" -User "jsmith@company.com" -AccessRights FullAccess -InheritanceType All

# 3. Grant Send As permission
Add-RecipientPermission -Identity "itsupport@company.com" -Trustee "bjohnson@company.com" -AccessRights SendAs -Confirm:$false
Add-RecipientPermission -Identity "itsupport@company.com" -Trustee "jsmith@company.com" -AccessRights SendAs -Confirm:$false

# 4. Verify permissions
Get-MailboxPermission -Identity "itsupport@company.com" | Where-Object {$_.User -like "*bjohnson*"}
Get-RecipientPermission -Identity "itsupport@company.com" | Where-Object {$_.Trustee -like "*bjohnson*"}

# 5. Check automapping (should appear automatically in Outlook)
Get-Mailbox "itsupport@company.com" | Select-Object *automap*

# If needed, disable automapping
Add-MailboxPermission -Identity "itsupport@company.com" -User "bjohnson@company.com" -AccessRights FullAccess -AutoMapping $false
```

### In Outlook (if not automapped)
1. File → Account Settings → Account Settings
2. Select email account → Change
3. More Settings → Advanced
4. Add shared mailbox address
5. OK → Next → Finish

### Success Criteria
- [ ] Shared mailbox created
- [ ] Users have Full Access
- [ ] Users have Send As rights
- [ ] Mailbox appears in Outlook
- [ ] Can send emails as shared mailbox

---

## Exercise 9: Bulk User Creation

**Difficulty:** Advanced  
**Time:** 40 minutes  
**Scenario:** Create 10 new users from CSV

### Background
HR provided list of 10 new employees starting next week. Create all accounts efficiently.

### Your Tasks

1. **Create CSV Template**
2. **Import and Validate Data**
3. **Create All Users**
4. **Assign to Groups**
5. **Generate Report**

### Solution

```powershell
# 1. Create CSV file (users.csv)
@"
FirstName,LastName,Username,Department,Title
Michael,Brown,mbrown,IT,System Admin
Lisa,Davis,ldavis,HR,HR Specialist
Tom,Wilson,twilson,Sales,Sales Rep
Emma,Moore,emoore,Finance,Accountant
James,Taylor,jtaylor,IT,Help Desk
"@ | Out-File C:\users.csv

# 2. Import CSV
$Users = Import-Csv C:\users.csv

# 3. Validate data
$Users | Format-Table -AutoSize

# 4. Create users
$Password = ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force
$Results = @()

foreach ($User in $Users) {
    try {
        New-ADUser `
            -Name "$($User.FirstName) $($User.LastName)" `
            -GivenName $User.FirstName `
            -Surname $User.LastName `
            -SamAccountName $User.Username `
            -UserPrincipalName "$($User.Username)@homelab.local" `
            -Path "OU=LabUsers,DC=homelab,DC=local" `
            -AccountPassword $Password `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -Department $User.Department `
            -Title $User.Title
        
        # Add to department group
        $GroupName = "$($User.Department)-Team"
        Add-ADGroupMember -Identity $GroupName -Members $User.Username -ErrorAction SilentlyContinue
        
        $Results += [PSCustomObject]@{
            Username = $User.Username
            FullName = "$($User.FirstName) $($User.LastName)"
            Status = "Success"
            Group = $GroupName
        }
        
        Write-Host "Created: $($User.Username)" -ForegroundColor Green
        
    } catch {
        $Results += [PSCustomObject]@{
            Username = $User.Username
            FullName = "$($User.FirstName) $($User.LastName)"
            Status = "Failed: $($_.Exception.Message)"
            Group = "N/A"
        }
        Write-Host "Failed: $($User.Username) - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 5. Generate report
$Results | Format-Table -AutoSize
$Results | Export-Csv C:\user-creation-report.csv -NoTypeInformation

# 6. Verify all users created
Get-ADUser -Filter {Enabled -eq $true} -SearchBase "OU=LabUsers,DC=homelab,DC=local" |
Where-Object {$_.SamAccountName -in $Users.Username} |
Select-Object Name, SamAccountName, Department
```

### Success Criteria
- [ ] All users created successfully
- [ ] Users in correct departments
- [ ] Users added to groups
- [ ] Report generated
- [ ] No errors in creation

---

## Exercise 10: Security Audit

**Difficulty:** Advanced  
**Time:** 45 minutes  
**Scenario:** Perform security audit on user accounts

### Your Tasks

1. **Find Inactive Accounts** (>90 days)
2. **Find Accounts with Password Never Expires**
3. **Find Accounts in Multiple Admin Groups**
4. **Find Disabled Accounts Still in Groups**
5. **Generate Compliance Report**

### Solution

```powershell
# 1. Find inactive accounts
$InactiveDays = 90
$InactiveDate = (Get-Date).AddDays(-$InactiveDays)

$InactiveUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |
Where-Object {$_.LastLogonDate -lt $InactiveDate -or $_.LastLogonDate -eq $null} |
Select-Object Name, SamAccountName, LastLogonDate, Enabled

Write-Host "`nInactive Users (>$InactiveDays days):" -ForegroundColor Yellow
$InactiveUsers | Format-Table -AutoSize

# 2. Password never expires
$PwdNeverExpires = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires |
Select-Object Name, SamAccountName, PasswordNeverExpires

Write-Host "`nAccounts with Password Never Expires:" -ForegroundColor Yellow
$PwdNeverExpires | Format-Table -AutoSize

# 3. Users in Domain Admins
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" |
Get-ADUser -Properties LastLogonDate, PasswordLastSet |
Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet

Write-Host "`nDomain Administrators:" -ForegroundColor Yellow
$DomainAdmins | Format-Table -AutoSize

# 4. Disabled users still in groups
$DisabledWithGroups = Get-ADUser -Filter {Enabled -eq $false} -Properties MemberOf |
Where-Object {$_.MemberOf -ne $null} |
Select-Object Name, SamAccountName, @{Name="GroupCount";Expression={$_.MemberOf.Count}}

Write-Host "`nDisabled Users Still in Groups:" -ForegroundColor Yellow
$DisabledWithGroups | Format-Table -AutoSize

# 5. Accounts with old passwords (>90 days)
$PasswordAge = 90
$PasswordDate = (Get-Date).AddDays(-$PasswordAge)

$OldPasswords = Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordLastSet |
Where-Object {$_.PasswordLastSet -lt $PasswordDate} |
Select-Object Name, SamAccountName, PasswordLastSet, @{Name="Age";Expression={(New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).Days}}

Write-Host "`nAccounts with Old Passwords (>$PasswordAge days):" -ForegroundColor Yellow
$OldPasswords | Format-Table -AutoSize

# 6. Generate full report
$Report = [PSCustomObject]@{
    AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm"
    InactiveAccounts = $InactiveUsers.Count
    PasswordNeverExpires = $PwdNeverExpires.Count
    DomainAdmins = $DomainAdmins.Count
    DisabledWithGroups = $DisabledWithGroups.Count
    OldPasswords = $OldPasswords.Count
}

Write-Host "`nSecurity Audit Summary:" -ForegroundColor Cyan
$Report | Format-List

# Export detailed findings
$InactiveUsers | Export-Csv C:\audit-inactive-users.csv -NoTypeInformation
$PwdNeverExpires | Export-Csv C:\audit-password-never-expires.csv -NoTypeInformation
$DisabledWithGroups | Export-Csv C:\audit-disabled-with-groups.csv -NoTypeInformation
$OldPasswords | Export-Csv C:\audit-old-passwords.csv -NoTypeInformation

Write-Host "`nReports exported to C:\" -ForegroundColor Green
```

### Remediation Actions

```powershell
# Disable inactive accounts
foreach ($User in $InactiveUsers) {
    Disable-ADAccount -Identity $User.SamAccountName
    Write-Host "Disabled: $($User.SamAccountName)" -ForegroundColor Yellow
}

# Remove disabled users from all groups except Domain Users
foreach ($User in $DisabledWithGroups) {
    $Groups = Get-ADPrincipalGroupMembership $User.SamAccountName | 
              Where-Object {$_.Name -ne "Domain Users"}
    
    foreach ($Group in $Groups) {
        Remove-ADGroupMember -Identity $Group -Members $User.SamAccountName -Confirm:$false
        Write-Host "Removed $($User.SamAccountName) from $($Group.Name)" -ForegroundColor Yellow
    }
}
```

### Success Criteria
- [ ] All inactive accounts identified
- [ ] Password policy violations found
- [ ] Admin accounts audited
- [ ] Disabled accounts cleaned up
- [ ] Reports generated
- [ ] Remediation actions documented

---

## Certification Practice Questions

### Question 1
A user calls reporting they can't log in. After 3 attempts their account is locked. What should you do FIRST?

A) Reset their password  
B) Unlock the account  
C) Disable the account  
D) Delete and recreate the account

**Answer: B** - Always unlock first, then troubleshoot why it was locked.

### Question 2
A user needs access to the Finance shared folder. What's the BEST way to grant access?

A) Give them direct NTFS permissions  
B) Add them to Finance-Team security group  
C) Share their personal folder to everyone  
D) Give them Domain Admin rights

**Answer: B** - Always use security groups for permission management.

### Question 3
User's Outlook won't connect after password change. What should they do?

A) Reinstall Office  
B) Clear cached credentials  
C) Create new Windows profile  
D) Rejoin domain

**Answer: B** - Clear cached credentials in Credential Manager.

---

## Next Steps

After completing these exercises:

1. **Practice Daily** - Repeat exercises until comfortable
2. **Time Yourself** - Improve resolution speed
3. **Document Everything** - Build your knowledge base
4. **Automate** - Create scripts for common tasks
5. **Get Certified** - Consider CompTIA A+, Network+, Microsoft certifications

These exercises cover 80% of real Help Desk tickets!
