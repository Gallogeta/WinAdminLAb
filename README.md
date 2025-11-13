# Windows Server & M365 Administration Homelab

![Lab Architecture](docs/images/lab-architecture.png)

## Project Overview

A production-grade Windows Server homelab environment running on Proxmox, designed to simulate enterprise Active Directory infrastructure and Microsoft 365 hybrid identity management. This project demonstrates hands-on experience with Windows Server administration, Active Directory, Group Policy, PowerShell automation, and cloud integration.

**Built for learning and showcasing enterprise IT administration skills.**

## Infrastructure Architecture

### Lab Components

```
┌─────────────────────────────────────────────────────────┐
│                  Proxmox Hypervisor                      │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Virtual Network: 192.168.100.0/24                 │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │ │
│  │  │   DC01       │  │   FS01       │  │  CLIENT1 │ │ │
│  │  │ Domain       │  │   Member     │  │ Win 10/11│ │ │
│  │  │ Controller   │  │   Server     │  │ Workst.  │ │ │
│  │  │              │  │              │  │          │ │ │
│  │  │ - AD DS      │  │ - File Share │  │ - Domain │ │ │
│  │  │ - DNS        │  │ - IIS        │  │   Joined │ │ │
│  │  │ - DHCP       │  │ - Print Svc  │  │ - User   │ │ │
│  │  │ - Azure AD   │  │              │  │   Testing│ │ │
│  │  │   Connect    │  │              │  │          │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────┘ │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌────────────────────────┐
              │   Microsoft 365        │
              │   - Azure AD           │
              │   - Exchange Online    │
              │   - SharePoint Online  │
              │   - Teams              │
              └────────────────────────┘
```

### Virtual Machines

| VM Name | OS | vCPU | RAM | Disk | IP Address | Role |
|---------|-----|------|-----|------|------------|------|
| DC01 | Windows Server 2022 | 2 | 4 GB | 60 GB | 192.168.100.10 | Domain Controller, DNS, DHCP |
| FS01 | Windows Server 2022 | 2 | 4 GB | 80 GB | 192.168.100.20 | File Server, IIS, Print Services |
| CLIENT1 | Windows 10/11 Pro | 2 | 4 GB | 60 GB | DHCP | Domain Client Workstation |

## Quick Start

### Prerequisites

- Proxmox VE 7.x or later
- Minimum 12 GB RAM available
- 200 GB free storage
- Windows Server 2022 ISO (evaluation or licensed)
- Windows 10/11 ISO (evaluation or licensed)
- Microsoft 365 trial account (optional, for hybrid setup)

### Setup Overview

1. **[Proxmox Setup](docs/01-proxmox-setup.md)** - Create VMs and network configuration
2. **[Domain Controller Setup](docs/02-domain-controller-setup.md)** - Install and configure AD DS
3. **[Member Server Setup](docs/03-member-server-setup.md)** - Join server to domain
4. **[Client Setup](docs/04-client-setup.md)** - Configure domain workstation
5. **[M365 Integration](docs/05-m365-integration.md)** - Hybrid identity with Azure AD Connect
6. **[Advanced Configuration](docs/06-advanced-configuration.md)** - GPO, security, monitoring

### Automated Deployment

Use the PowerShell scripts in the `scripts/` directory to automate common tasks:

```powershell
# On Domain Controller - Initial AD setup
.\scripts\01-Initialize-DomainController.ps1

# Create OUs, users, and groups
.\scripts\02-Create-ADStructure.ps1

# Configure Group Policies
.\scripts\03-Configure-GroupPolicies.ps1

# Setup file shares and permissions
.\scripts\04-Configure-FileShares.ps1
```

## Documentation

- **[Setup Guides](docs/)** - Step-by-step installation instructions
- **[PowerShell Scripts](scripts/)** - Automation and management scripts
- **[Lab Exercises](exercises/)** - Hands-on practice scenarios
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions
- **[Best Practices](docs/best-practices.md)** - Enterprise-grade configurations

## Skills Demonstrated

### Windows Server Administration
- Active Directory Domain Services (AD DS)
- Group Policy Objects (GPO) management
- DNS and DHCP configuration
- File and Print Services (NTFS/Share permissions)
- Remote Desktop Services
- Windows Server Update Services (WSUS)
- Server backup and disaster recovery

### PowerShell Automation
- User and group provisioning
- Bulk AD operations
- System configuration automation
- Reporting and auditing scripts
- Scheduled task automation

### Microsoft 365 & Hybrid Identity
- Azure AD Connect configuration
- Hybrid identity management
- Exchange Online hybrid deployment
- Single Sign-On (SSO) setup
- Multi-Factor Authentication (MFA)
- Conditional Access policies

### Security & Compliance
- Security baseline implementation
- Audit policy configuration
- Password and account policies
- User rights and privileges management
- Windows Firewall configuration

### Virtualization
- Proxmox VM management
- Virtual networking configuration
- Snapshot and backup strategies
- Resource allocation and monitoring

## Lab Exercises

Hands-on scenarios to practice real-world administration tasks:

1. **[User Management](exercises/01-user-management.md)** - Onboarding/offboarding workflows
2. **[Group Policy Deployment](exercises/02-group-policy.md)** - Desktop configuration and security
3. **[File Server Management](exercises/03-file-server.md)** - Shares, permissions, DFS
4. **[Disaster Recovery](exercises/04-disaster-recovery.md)** - Backup and restore procedures
5. **[Security Hardening](exercises/05-security-hardening.md)** - Implement security baselines
6. **[M365 User Sync](exercises/06-m365-sync.md)** - Hybrid identity scenarios
7. **[Troubleshooting Lab](exercises/07-troubleshooting.md)** - Fix common issues

## Useful PowerShell Commands

```powershell
# Check AD replication status
repadmin /replsummary

# List all domain users
Get-ADUser -Filter * -Properties *

# Check Group Policy application
gpresult /r

# Test domain connectivity
Test-ComputerSecureChannel -Verbose

# View domain controller diagnostics
dcdiag /v

# Azure AD Connect sync status
Get-ADSyncScheduler
Start-ADSyncSyncCycle -PolicyType Delta
```

## Future Enhancements

- [ ] Add second Domain Controller for redundancy
- [ ] Implement Certificate Services (PKI)
- [ ] Setup WSUS for patch management
- [ ] Deploy Remote Desktop Services (RDS)
- [ ] Configure VPN access
- [ ] Implement DFS replication
- [ ] Add monitoring with PRTG/Zabbix
- [ ] Setup backup solution (Veeam)

## Learning Resources

- [Microsoft Learn - Windows Server](https://learn.microsoft.com/en-us/windows-server/)
- [Microsoft Learn - Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/)
- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [Active Directory Best Practices](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

## License

This project is for educational purposes. Windows Server and Microsoft 365 require appropriate licensing for production use.

## Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your LinkedIn](https://linkedin.com/in/yourprofile)
- Portfolio: [yourwebsite.com](https://yourwebsite.com)

## Acknowledgments

Built as part of my journey to master Windows Server administration and cloud integration. Special thanks to the Microsoft documentation team and the homelab community.

---

**Star this repo if you find it helpful!**
