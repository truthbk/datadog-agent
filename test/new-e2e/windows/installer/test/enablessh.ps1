<#
.SYNOPSIS

Installs and configures OpenSSH Server on a Hyper-V VM

.PARAMETER VMName

Name of the Hyper-V VM

.PARAMETER SSHKeyPath

Optional path to SSH Public Key to add to administrators_authorized_keys

.PARAMETER Credential

Optional PSCredential for the Hyper-V VM PSSession. Will prompt if not provided.

.PARAMETER SnapshotName

Optional name of snapshot to create after completion

.EXAMPLE

PS> .\enablessh.ps1 -VMName "Windows Server 2019" -Credential (Get-Credential) -SnapshotName ssh

#>
param (
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    [string]$SSHKeyPath,
    [string]$SnapshotName,
    [ValidateNotNull()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
)

if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
    $Credential = Get-Credential
}

$s = New-PSSession -VMName $VMName -Credential $Credential

# Install OpenSSH Server
Invoke-Command -Session $s -ScriptBlock {
    # This command does NOT install a consistent version across Windows versions, this lead to
    # compatability issues (different command line quoting rules).
    # Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    start-process -passthru -wait msiexec.exe -args '/i https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.2.2.0p1-Beta/OpenSSH-Win64-v9.2.2.0.msi /qn'

    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    } else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }

    # Set powershell default shell
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force

    # enable+start ssh service
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service -Name sshd

    # Wait for files to be populated
    while (!(Test-Path "$env:programdata\ssh\ssh_host_rsa_key")) {
        Start-Sleep 10
    }

    # Fix authorized_keys privs
    if (!(Test-Path "$env:programdata\ssh\administrators_authorized_keys")) {
        New-Item -ItemType File -Path "$env:programdata\ssh\administrators_authorized_keys"
    }
    get-acl "$env:programdata\ssh\ssh_host_rsa_key" | set-acl "$env:programdata\ssh\administrators_authorized_keys"
}

if ($SSHKeyPath) {
    # Add SSH Key
    $sshkey = (Get-Content -Path $SSHKeyPath)
    Invoke-Command -Session $s -ScriptBlock { Add-Content -Path "$env:programdata\ssh\administrators_authorized_keys" -Value $Using:sshkey}
}

# Print connection info
Invoke-Command -Session $s -ScriptBlock {
    ipconfig
    ssh-keygen -l -f C:\ProgramData\ssh\ssh_host_ecdsa_key
    ssh-keygen -l -f C:\ProgramData\ssh\ssh_host_ed25519_key
    ssh-keygen -l -f C:\ProgramData\ssh\ssh_host_rsa_key
}

if ($SnapshotName) {
    # Note: checkpoint-vm breaks the session
    Checkpoint-VM -Name $VMName -SnapshotName $SnapshotName
}

