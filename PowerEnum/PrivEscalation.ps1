<#
.SYNOPSIS
Windows Enumeration for Priv Escalation (Level 1 && 2)

.DESCRIPTION
Powershell Script for Enumeration/Scanning possible permissions flaws or vulnerabilities in improper system configurations.

.EXAMPLE
- Default - normal operation with username/password audit in drives/registry
.\powerEnum.ps1

- Look For Possible passwords && Usernames (ALL file extensions)
# Beware of false positives or unwanted results
.\powerEnum.ps1 -LookForCredentials

- Look for Possible passwords && Usernames (Customized)
# Beware of false positives or unwanted results
.\powerEnum.ps1 -LookForCredentials -Extensions ".txt,.xml"

- Search for file extensions
.\powerEnum.ps1 -Searchfiles -Extensions ".txt,.xml"

- Display Help
.\powerEnum.ps1 -h/-help

.NOTES
[+] I have a lot of admiration and respect for the work of https://github.com/peass-ng 
(from whom I learned to put this script together). 

[+] Sources such as: https://book.hacktricks.wiki/ have been of great use and learning.

[+] I intend to continue my studies and add/improve the processes I have written in this script.
#>

####################### FUNCTIONS #######################

[CmdletBinding()]

param (
    [Alias("h", "help")]
    [switch] $HelpMessage,
    [switch] $LookForCredentials,
    [switch] $Searchfiles,
    [string] $Extensions
)

function Write-Color {
    param (
        [string] $Text,
        [string] $Color
    )
    Write-Host -ForegroundColor $Color $Text -NoNewline
}

function Search-FilesForSensitiveData {
    [CmdletBinding()]
    param (
        [switch]$LookForCredentials,
        [string[]]$Extensions
    )

    if ($Extensions -and $Extensions.Count -eq 1 -and $Extensions[0] -like "*,*") {
        $Extensions = $Extensions[0] -split "," | ForEach-Object {
            if ($_ -notlike '.*') { ".$_" } else { $_ }
        }
    }    

    $patterns = @()

    if ($LookForCredentials) {
        $patterns += @(
            "password\s*[:=]\s*.+",
            "senha\s*[:=]\s*.+",
            "pass.*[=:].+",
            "pwd.*[=:].+",
            "secret\s*[:=]\s*.+",
            "client[_\-]?secret\s*[:=]\s*.+",
            "api[_\-]?key\s*[:=]\s*.+",
            "access[_\-]?token\s*[:=]\s*.+",
            "bearer\s+[a-zA-Z0-9\-_=]+\.*[a-zA-Z0-9\-_=]*",
            "authorization\s*[:=]?\s*(Basic|Bearer)?\s+[a-zA-Z0-9\-\._~\+\/]+=*",
            "user(name)?\s*[:=]\s*.+",
            "login\s*[:=]\s*.+",
            "usuario\s*[:=]\s*.+",
            "username[=:].+",
            "user[=:].+",
            "login[=:].+",
            "net user .+ /add",
            "utilisateur\s*[:=]\s*.+",
            "usuário\s*[:=]\s*.+",
            "benutzer\s*[:=]\s*.+",
            "user id\s*[:=]\s*.+",
            "username\s*[:=]\s*.+",
            "account\s*[:=]\s*.+",
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}",
            "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]"
        )
    }

    $usingCustomExtensions = $Extensions -and $Extensions.Count -gt 0

    if ($usingCustomExtensions) {
        $textExtensions = $Extensions
    } 
    
    else {
        $textExtensions = '.txt', '.log', '.ini', '.conf', '.xml', '.html', '.htm', '.csv', '.json', '.env'
    }

    $ignoreNames = 'license', 'eula', 'about', 'copyright', 'readme', 'strings', 'locales', 'messages'
    $maxLines = 40
    $maxLineLength = 300

    $drives = Get-PSDrive -PSProvider 'FileSystem'

    foreach ($drive in $drives) {
        try {
            
            Get-ChildItem -Path "$($drive.Name):\" -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object {
                $textExtensions -contains $_.Extension.ToLower() -and
                ($ignoreNames -notcontains $_.BaseName.ToLower())
            } |
            
            ForEach-Object {
                $matchesFound = @()
                $lineCount = 0
                $limitReached = $false

                try {
                    
                    $lines = Get-Content -Path $_.FullName -ErrorAction Stop
                    foreach ($line in $lines) {
                        if ($line.Length -gt $maxLineLength) { continue }

                        foreach ($pattern in $patterns) {
                            if ($line -match $pattern) {
                               
                                $matchesFound += $line.Trim()
                                $lineCount++
                                break
                            }
                        }

                        if ($lineCount -ge $maxLines) {
                           
                            $limitReached = $true
                            break
                        }
                    }
                } catch {
                    Write-Verbose "Cannot read file: $($_.FullName)"
                }

                if ($matchesFound.Count -gt 0) {
                    
                    Write-Host "`n[!] Potential matches in file: $($_.FullName)" -ForegroundColor Red
                    foreach ($m in $matchesFound | Select-Object -Unique) {
                        Write-Host "     > $m" -ForegroundColor DarkYellow
                    }

                    if ($limitReached) {
                        Write-Host "     [!] File has reached the 40-line limit. Output canceled." -ForegroundColor Magenta
                    }
                }
            }
        } catch {
            Write-Warning "Could not search in drive $($drive.Name): $_"
        }
    }
}

function Search-FilesByExtension {
    [CmdletBinding()]
    param (
        [switch]$Searchfiles,
        [string[]]$Extensions
    )

    if ($Extensions -and $Extensions.Count -eq 1 -and $Extensions[0] -like "*,*") {
        $Extensions = $Extensions[0] -split "," | ForEach-Object {
            if ($_ -notlike '.*') { ".$_" } else { $_ }
        }
    }    

    if (-not $Searchfiles) {
        
        Write-Warning "You must specify -Searchfiles to use this function."
        return
    }

    if (-not $Extensions -or $Extensions.Count -eq 0) {
        
        Write-Error "You must specify -Extensions when using -Searchfiles."
        return
    }

    $drives = Get-PSDrive -PSProvider 'FileSystem'

    foreach ($drive in $drives) {
        try {
            
            Get-ChildItem -Path "$($drive.Name):\" -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $Extensions -contains $_.Extension.ToLower() } |
            Select-Object FullName, Length, LastWriteTime |
            Sort-Object FullName |
            Format-Table -AutoSize
        } 
        
        catch {
            Write-Warning "Could not search in drive $($drive.Name): $_"
        }
    }
}

# -> CAPTURING CLIPBOARD CONTENT (IF ENABLED)
function Get-ClipboardContent {
    try {
    
        if (-not [System.Reflection.Assembly]::LoadWithPartialName("PresentationCore")) {
            Write-Host "Error loading the PresentationCore library."
            return
        }

        $clipboardContent = [Windows.Clipboard]::GetText()

        if ($clipboardContent) {
            Write-Host $clipboardContent
        } 
        
        else {
            Write-Host "The clipboard is empty."
        }
    } 
    
    catch {
        Write-Host "An error occurred while accessing the clipboard: $_"
    }   
}

# -> THIS FUNCTION IS NOT MINE, THAT'S WHY IT'S SO GOOD!!!
# -> COLLECTS DETAILED INFORMATION ABOUT THE INSTALLED AV
function Get-AntiVirusProduct {
    [CmdletBinding()]
    param (
    [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('name')]
    $computername=$env:computername
    )

    $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

    $ret = @()
    foreach($AntiVirusProduct in $AntiVirusProducts){
        #The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
        
        switch ($AntiVirusProduct.productState) {
        "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }

        $ht = @{}
        $ht.Computername = $computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
        $ht.'Definition Status' = $defstatus
        $ht.'Real-time Protection Status' = $rtstatus

        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    
    Return $ret
} 

# -> LISTING HOTFIXES FOR VULN SEARCH
function CheckHotFixes {

    $OS_HotFixes = Get-HotFix -Description "Update" | Select-Object HotFixId, InstalledOn
    return $OS_HotFixes | Format-Table -Property HotFixId, InstalledOn -AutoSize
}

# -> GENERIC FUNCTION (CHECKS ENABLED KEYS)
function CheckEnabledKeys {
    param (
        [string] $keyPath,
        [string] $keyName
    )

    if (-not (Test-Path $keyPath)) {
        Write-Color "Registry path not found: $keyPath" "Red"
        return
    }

    try {
        $item = Get-ItemProperty -Path $keyPath -ErrorAction Stop
        if ($null -eq $item.$keyName) {
            Write-Color "Key '$keyName' not found at path: $keyPath" "Red"
            return
        }

        if ($keyName -eq "CACHEDLOGONSCOUNT") {
            Write-Output "$($item.$keyName)"
            return
        }

        switch ($item.$keyName) {
            0 { Write-Color "[0] Disabled" "Yellow" }
            1 { Write-Color "[1] Enabled/Found!!" "Green" }
            
            default { Write-Color "Unexpected key value: $($item.$keyName)" "Yellow" }
        }
    }
    catch {
        Write-Color "[X] Error reading registry value: $_" "Red"
    }
}


# -> THIS WILL CHECK FOR LSA PROTECTION!
function CheckLSA {
    try {
        $check1 = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\LSA).RunAsPPL
    
        switch ($check1) {
            2 { Write-Host "Enabled without UEFI Lock" }
            1 { Write-Host "Enabled with UEFI Lock" }
            0 { Write-Color "Protection is Disabled!!" "Green" }
    
            Default { Write-Color "The system was unable to find the specified registry value" "red"}
        }
    } 
    
    catch {
        return "Unexpected registry value: $keyValue"
    }
}

# -> THIS WILL CHECK FOR ENABLELUA (UAC SETTING)
function CheckUACSettings {
    try {
        $Enabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop).EnableLUA
        
        if ($EnableLUA -eq 1) {
            Write-Host "EnableLua is set to 1. UAC Features are active!"
        }
        else {
            Write-Color "EnableLUA is not active!!" "Green"
        }
    }
    catch {
        Write-Color "[X] Could not read EnableLUA setting." "Red"
    }
}

# -> THIS WILL CHECK FOR LAPS AND CREDENTIAL GUARD
function CheckLAPS_And_CredentialGuard {
    [CmdletBinding()]
    param ()


    # ########## Check Credential Guard ########### #
    
    try {
        
        $lsaCfg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -ErrorAction Stop
        switch ($lsaCfg.LsaCfgFlags) {
            2 { Write-Host "Value: 2 - Credential Guard Enabled (without UEFI Lock)" }
            1 { Write-Host "Value: 1 - Credential Guard Enabled (with UEFI Lock)" }
            0 { Write-Color "Value: 0 - Credential Guard Disabled!" "Green" }
            
            Default { Write-Color "LsaCfgFlags: Unknown value - $($lsaCfg.LsaCfgFlags)`n" "Red" }
        }
    } 
    
    catch {
        Write-Warning "Could not access LSA registry key (LsaCfgFlags)."
    }

    # ######## LAPS Check ######### #
    Write-Color "`nLAPS (Local Admin Password Solution) Check: " "Yellow"
    $lapsPaths = @(
        "C:\Program Files\LAPS\CSE\Admpwd.dll",
        "C:\Program Files (x86)\LAPS\CSE\Admpwd.dll"
    )
    $lapsFound = $false

    foreach ($path in $lapsPaths) {
        
        if (Test-Path $path) {
        
            Write-Color "LAPS DLL found: $path" "Green"
            $lapsFound = $true
        }
    }

    if (-not $lapsFound) {
        Write-Color "LAPS DLL not found on this machine." "Red"
    }

    try {
        $lapsPolicy = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft Services\AdmPwd" -ErrorAction Stop
        
        if ($lapsPolicy.AdmPwdEnabled -eq 1) {
            Write-Color "LAPS GPO is enabled via registry." "Green"
        } 
        
        else {
            Write-Color "LAPS GPO found but not enabled." "Orange"
        }
    } 
    
    catch {
        Write-Color "LAPS GPO registry key not found." "Red"
    }
}

# -> THIS WIll LIST INSTALLED APPLICATIONS (WITH SOME DETAILED INFO)
function Get-InstalledApplications {
    [CmdletBinding()]
    param ()

    $apps = @()

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $registryPaths) {
        
        try {
            $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and $_.DisplayName -ne "" } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

            $apps += $entries
        } 
        
        catch {
            Write-Warning "Could not read from registry path: $path"
        }
    }

    if ($apps.Count -eq 0) {
        Write-Color "No applications found." "Red"
    } 
    
    else {
        $apps | Sort-Object DisplayName | Format-Table -AutoSize `
            @{Name='Application'; Expression={$_.DisplayName}},
            @{Name='Version'; Expression={$_.DisplayVersion}},
            @{Name='Publisher'; Expression={$_.Publisher}},
            @{Name='Install Date'; Expression={ 
                
            if ($_.InstallDate -match '^\d{8}$') {
                [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null).ToShortDateString()
            } 
            else {
                $null
            }
        }}
    }
}

# -> THIS WILL PRINT RECENT COMMANDS FROM (HCKU/POWERSHELL/RECENT DOCS/PREFETCH FOLDER)
# -> It can be useful
function Get-RecentlyRunCommands {
    Write-Color "`nHKCU recent commands: " "Blue"

    if ($runMRUKey) {
        
        $properties = $runMRUKey.Property | Where-Object { $_ -ne "MRUList" }
        $entries = @()
    
        foreach ($prop in $properties) {
            $value = $runMRUKey.GetValue($prop)
        
            if ($value) {
        
                Write-Output "`n"
                $entries += "$prop : $value"
            }
        }
    
        if ($entries.Count -gt 0) {
            $entries | ForEach-Object { Write-Host $_ }
        } 
        
        else {
            Write-Color "[!] Empty!" "DarkYellow"
        }
    } 
    
    else {
        Write-Color "[X] Could not retrieve RunMRU registry key." "Red"
    }

    Write-Color "`n`nPowerShell History (PSReadLine):`n" "Blue"
    $psHistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    
    if (Test-Path $psHistoryPath) {
        Get-Content $psHistoryPath -Tail 20 | ForEach-Object { Write-Host $_ }
    } 
    
    else {
        Write-Color "No PowerShell history file found." "Red"
    }

    Write-Color "`nRecently Opened Files (RecentDocs) (Might be interesting):`n" "Blue"
    $recentDocsKey = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -ErrorAction SilentlyContinue
   
    if ($recentDocsKey) {
       
        foreach ($subKey in $recentDocsKey) {
            
            $key = Get-ItemProperty -Path $subKey.PSPath -ErrorAction SilentlyContinue
            $key.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
   
                $val = $_.Value -as [byte[]]
   
                if ($val) {
                    
                    try {
                        $str = [System.Text.Encoding]::Unicode.GetString($val) -replace '\x00', ''
                        Write-Host $str
                    } 
                    
                    catch {}
                }
            }
        }
    }
    
    else {
        Write-Color "RecentDocs registry key not found." "Red"
    }

    Write-Color "`nExecutables from Prefetch Folder (Might be interesting):`n" "Blue"
    $prefetchPath = "$env:SystemRoot\Prefetch"
    
    if (Test-Path $prefetchPath) {
       
        try {
            Get-ChildItem $prefetchPath -Filter *.pf -ErrorAction Stop | Select-Object -First 20 | ForEach-Object {
                Write-Host $_.Name
            }
        } 
        
        catch {
            Write-Color "[X] Could not access Prefetch folder. Administrator privileges might be required.`n" "Red"
        }
    } 
    
    else {
        Write-Color "Prefetch folder not accessible or disabled." "Red"
    }
}

# -> THIS WILL LIST SHARED DIRs WITH PERMISSIONS
function Get-SmbShareWithPermissions {
    if (-not (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)) {
        
        Write-Color "SMB is not available or not enabled on this system. `n" "Red"
        return
    }

    $userGroups = whoami.exe /groups /fo csv |
        Select-Object -Skip 2 |
        ConvertFrom-Csv -Header 'GroupName' |
        Select-Object -ExpandProperty GroupName

    $shares = Get-SmbShare | Get-SmbShareAccess

    if (-not $shares) {
       
        Write-Color "No available SMB shares found on this system. `n" "Red"
        return
    }

    $foundMatch = $false

    foreach ($share in $shares) {
        foreach ($group in $userGroups) {
            
            $isSameGroup = ($share.AccountName -like $group)
            $hasPermission = $share.AccessRight -in @('Full', 'Change')
            $isAllowed = $share.AccessControlType -eq 'Allow'

            if ($isSameGroup -and $hasPermission -and $isAllowed) {
                
                Write-Output "`n"
                Write-Color "$($share.AccountName) has $($share.AccessRight) access to share '$($share.Name)'" "Green"
                $foundMatch = $true
            }
        }
    }

    if (-not $foundMatch) {
        Write-Color "No SMB share permissions matched your current user groups. `n" "Red"
    }
}

# -> GENERIC FUNCTION TO CHECK PERMISSIONS
function Check-Permissions {
    param(
        [Parameter(Mandatory=$true)][string]$Target
    )

    if (-not (Test-Path $Target)) {
        Write-Color "Path not found: $Target`n" "Red"
        return
    }

    try {
        $acl = Get-Acl -Path $Target
    } 
    
    catch {
        Write-Color "Failed to read ACL for $Target`n" "Red"
        return
    }

    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $groups = (whoami /groups /fo csv | Select-Object -Skip 2 | ConvertFrom-Csv -Header "GroupName") | Select-Object -ExpandProperty GroupName
    $identities = @($user) + $groups

    $found = $false

    foreach ($entry in $acl.Access) {
        
        foreach ($id in $identities) {
        
            if ($entry.IdentityReference -like "*$id") {
        
                $perm = $entry.FileSystemRights
                if ($perm -match "FullControl|Modify|Write") {
                    $found = $true
        
                    Write-Color "`n`n[!] Potential misconfigured access" "Green"
                    Write-Color "`n -> " "Yellow" 
                    Write-Color "Identity '$($entry.IdentityReference)' has '$perm' on '$Target'" "White"
                }
            }
        }
    }

    if (-not $found) {
        Write-Color "`nNo concerning permissions found for $Target`n" "Red"
    }
}


# -> THIS WILL CHECK FOR VULN SCHEDULES 
function Check-ScheduledTasksAccess {
    $tasksPath = "C:\Windows\System32\Tasks"

    if ((Test-Path $tasksPath) -and (Get-ChildItem $tasksPath -ErrorAction SilentlyContinue)) {
        
        Write-Color "Access confirmed!! Proceed from here:`n" "Green"
        Write-Color "-> $tasksPath`n`n" "Blue"

        
        Get-ChildItem $tasksPath | ForEach-Object {
            Write-Host " - $($_.FullName)`n"
        }
    }
    
    else {
        
        Write-Color "`nNo admin access to $tasksPath. Listing non-Microsoft scheduled tasks instead...`n" "Red"

        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
            $taskInfo = $_ | Get-ScheduledTaskInfo
            $Actions = $_.Actions.Execute
            
            if ($Actions) {
                foreach ($a in $Actions) {
                    $resolvedPath = $a -replace '"', ''
                    
                    $resolvedPath = $resolvedPath -replace "%windir%", $env:windir
                    $resolvedPath = $resolvedPath -replace "%SystemRoot%", $env:windir
                    $resolvedPath = $resolvedPath -replace "%localappdata%", "$env:UserProfile\AppData\Local"
                    $resolvedPath = $resolvedPath -replace "%appdata%", $env:AppData

                    Check-Permissions -Target $resolvedPath

                    Write-Color "`n`nTaskName: $($_.TaskName)`n" "Cyan"
                    Write-Host "--------------------------------------------"
                    
                    [PSCustomObject]@{
                        LastResult = $taskInfo.LastTaskResult
                        NextRun    = $taskInfo.NextRunTime
                        Status     = $_.State
                        Command    = $_.Actions.Execute
                        Arguments  = $_.Actions.Arguments
                    } | Format-List
                }
            }
        }
    }
}


# -> THIS FUNCTION WILL LIST PROCEEDINGS WITH WRITING, EDITING OR TOTAL CONTROL PERMISSIONS
function Get-ProcessInfo {
    Write-Host "`n"

    $processes = Get-Process | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique
    
    foreach ($processPath in $processes) {
        
        Write-Color "`n-> " "yellow"
        Write-Host "Process Path: $processPath"
        
        if ($null -ne $processPath) {
            
            try {
                $ACLObject = Get-Acl $processPath -ErrorAction SilentlyContinue
            }
            
            catch {
                Write-Color "Error: Could not retrieve ACL for $processPath" "Red"
                continue
            }

            if ($ACLObject) {
                $userPermissions = @()

                $identities = @("$env:COMPUTERNAME\$env:USERNAME")
                $identities += (whoami.exe /groups /fo csv | Select-Object -Skip 2 | ConvertFrom-Csv -Header 'group name' | Select-Object -ExpandProperty 'group name')

                foreach ($identity in $identities) {
               
                    $ACLObject.Access | Where-Object { $_.IdentityReference -like $identity } | ForEach-Object {
               
                        $permission = ""

                        switch -Wildcard ($_.FileSystemRights) {
                            "FullControl" { $permission = "FullControl" }
                            "Write*" { $permission = "Write" }
                            "Modify" { $permission = "Modify" }
                        }

                        if ($permission) {
                            $userPermissions += "$identity has '$permission' permissions"
                        }
                    }
                }

                if ($userPermissions.Count -gt 0) {
                    Write-Color "Permissions for ${processPath}: `n" "Green"
                    $userPermissions | ForEach-Object { Write-Host $_ }
                } 
               
                else {
                    Write-Color "No specific user permissions found for $processPath`n" "DarkRed"
                }
            }
        }
    }
}

# -> Another function to validate other types of configuration/key
function CheckValues($value, $label) {
    if ($null -eq $value -or $value -eq "") {
        Write-Color "${label}: No Value has been found! `n" "red"
    } else {
        Write-Output "${label}: $value"
    }
}

#########################################################

###################### OPERATIONS #######################

if (-not $LookForCredentials -and -not $Searchfiles -and -not $HelpMessage) {
    
    Write-Output ("{0,-50}" -f"======================================================")
    
    $OS_info = Get-ComputerInfo -Property WindowsProductName 
    $OS_Version = Get-ComputerInfo -Property OSVersion | Select-Object -ExpandProperty OSVersion
    $Output_info = $OS_info -replace ".*=" -replace "}"
    $OS_Hostname = [System.Environment]::UserDomainName
    $OS_CurrentUsername = [System.Environment]::UserName
    $OS_SystemUsers = Get-WmiObject -Class Win32_UserAccount | Select-Object Name 
    $Output_Users = $OS_SystemUsers | ForEach-Object { $_.Name } 
    $Home_Folders = Get-ChildItem C:\Users

    Write-Color "`nOperational System: " "Green"
    Write-Host "$Output_info | $OS_Version"
    Write-Color "Hostname: " "Green"
    Write-Host $OS_Hostname
    Write-Color "Current Username: " "Green"
    Write-Host $OS_CurrentUsername
    Write-Color "Other Users: " "Green"
    Write-Host ($Output_Users -join ", ") "`n"  
    Write-Color "Home Folders: "  "Green"
    Write-Host ($Home_Folders -join ", ") "`n"
    Write-Output ("{0,-50}`n" -f"======================================================")

    Write-Color "Users directory (read acess): `n" "Magenta"
    
    Get-ChildItem C:\Users\* | ForEach-Object {
        if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
            
            Write-Color "`n->" "Yellow"
            Write-Color " Read Access to $($_.FullName)" "Green"
        }
    }

    Write-Output ("`n`n{0,-50}`n" -f"======================================================")

    $defaultDomain = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultDomainName
    $defaultUser = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultUserName
    $defaultPassword = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").DefaultPassword
    $altDefaultDomain = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultDomainName
    $altDefaultUser = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultUserName
    $altDefaultPassword = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").AltDefaultPassword

    Write-Color "`nDefault Domain " "Magenta"
    CheckValues $defaultDomain
    Write-Color "Default User " "Magenta"
    CheckValues $defaultUser
    Write-Color "Default Password " "Magenta"
    CheckValues $defaultPassword
    Write-Color "Alternate Default Domain " "Magenta"
    CheckValues $altDefaultDomain
    Write-Color "Alternate Default User " "Magenta"
    CheckValues $altDefaultUser
    Write-Color "Alternate Default Password " "Magenta"
    CheckValues $altDefaultPassword
    
    Write-Color "`n`nRemote Sessions: `n`n" "Magenta"
    try { qwinsta } catch { Write-Host "'qwinsta' command not present on system" }

    Write-Color "`nCurrent Logged on Users: `n`n" "Magenta"
    try { quser }catch { Write-Host "'quser' command not not present on system" } 

    Write-Output ("`n`n{0,-50}`n" -f"======================================================")

    Write-Color "`nCurrent Privileges: `n`n" "Magenta"
    whoami /priv

    Write-Output ("`n`n{0,-50}`n" -f"======================================================")

    Write-Color "Antivirus: " "Magenta"
    Get-AntiVirusProduct

    Write-Output ("{0,-50}`n" -f"======================================================")

    Write-Color "Installed Applications: " "Magenta"
    Get-InstalledApplications

    Write-Output ("{0,-50}`n" -f"======================================================")

    Write-Color "Process Info/Permissions: " "Magenta"
    Get-ProcessInfo

    Write-Output ("`n{0,-50}`n" -f"======================================================")

    Write-Color "`Checking access to scheduled tasks folder:`n" "Magenta"
    Check-ScheduledTasksAccess

    Write-Output ("`n{0,-50}`n" -f"======================================================")

    Write-Color "HotFixes: `n" "Yellow"
    CheckHotFixes

    Write-Output ("{0,-50}`n" -f"======================================================")

    Write-Color "AlwaysInstallElevated (HKCU): " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -keyName 'AlwaysInstallElevated')"

    Write-Color "AlwaysInstallElevated (HKLM): " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -keyName 'AlwaysInstallElevated')`n"

    Write-Color "WDigest (Plain-Text Password Storage LSASS): " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -keyName 'UseLogonCredential')`n"

    Write-Color "Cached WinLogon Credentials: " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -keyName 'CACHEDLOGONSCOUNT')`n"

    Write-Color "Checking SNMP Passwords: " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKLM:\SYSTEM\CurrentControlSet\Services\' -keyName 'SNMP')`n"

    Write-Color "Checking WinVNC Passwords: " "Yellow"
    Write-Host "$(CheckEnabledKeys -keyPath 'HKCU:\Software\ORL\WinVNC3\' -keyName 'Password')`n"

    Write-Color "Checking LSA Protection...: " "Yellow"
    CheckLSA

    Write-Color "`n`nChecking UAC Settings...: " "Yellow"
    CheckUACSettings

    # ################# Checking Audit Log Settings and WEF #################  
    
    Write-Color "`n`nChecking Windows Event Forwarding: " "Yellow"
    if (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager) {
        Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
    }
    
    else {
        Write-Color "The log entry was not found, it is not possible know where the logs are being saved.`n" "Red"
    }

    Write-Color "`nChecking Audit Log Settings: " "Yellow"
    if ((Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\).Property) {
        Get-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
    }
   
    else {
        Write-Color "The system was unable to find the Audit Log settings, registry key or value.`n" "Red"
    }
    
    Write-Color "`nCredential Guard Check: " "Yellow"
    CheckLAPS_And_CredentialGuard
    Write-Host "`n"
    
    # #######################################################################

    if (Test-Path HKCU:\Software\OpenSSH\Agent\Keys) {
        Write-Color "`n[+] " "Green"
        Write-Output "OpenSSH keys found! Try Extracting the keys! `n"
    }
   
    else {
        Write-Color "`n[X] " "Red"
        Write-Output "No OpenSSH Keys found!" 
    }

    Write-Output ("`n{0,-50}`n" -f"======================================================")
    Write-Color "Clipboard info:`n`n" "Yellow" 
    Write-Color "Trying to read clipboard info...`n" "Blue" 
    Get-ClipboardContent

    Write-Output ("`n{0,-50}`n" -f"======================================================")
    
    Write-Color "Extracting windows command history...:`n" "Yellow"
    Get-RecentlyRunCommands

    Write-Output ("`n{0,-50}`n" -f"======================================================")

    Write-Color "Trying to read wifi passwords: `n" "Yellow"
    netsh wlan show profiles |
    Select-String "All User Profile\s*:\s*(.+)" |
    
    ForEach-Object {
        $profileName = $_.Matches[0].Groups[1].Value.Trim()
        netsh wlan show profile name="$profileName" key=clear
    }
    
    Write-Output ("`n{0,-50}`n" -f"======================================================")

    Write-Color "Listing SMBSHARES with acess permissions: " "Yellow"
    Get-SmbShareWithPermissions

    Write-Output ("`n{0,-50}`n" -f"======================================================")
    
    Write-Color "Checking PowerShell Execution Policy:`n" "Yellow"

    try {
        $execPolicy = Get-ExecutionPolicy -List
        
        foreach ($scope in $execPolicy.Keys) {
            $policy = $execPolicy[$scope]
            Write-Color "Scope: " "Cyan"
            Write-Host "$scope - Policy: $policy"
        }

        if ($execPolicy['LocalMachine'] -eq 'Restricted') {
            Write-Color "`n[!] Execution policy at LocalMachine scope is set to 'Restricted' (scripts are disabled).`n`n" "Red"
        }
        
        elseif ($execPolicy['LocalMachine'] -eq 'Unrestricted' -or $execPolicy['LocalMachine'] -eq 'Bypass' -or $execPolicy['LocalMachine'] -eq 'Undefined') {
            Write-Color "`n[+] Execution policy at LocalMachine scope allows script execution: $($execPolicy['LocalMachine']).`n`n" "Green"
        }
    }
   
    catch {
        Write-Color "`n[X] Failed to retrieve execution policy information.`n`n" "Red"
    }

}

if ($LookForCredentials) {
   
    Write-Color "[+] Searching for passwords and usernames...:`n" "Cyan"

    if ($Extensions) {
        
        Write-Color "-> " "Yellow"
        Write-Color "Selected Extensions: $Extensions`n" "Cyan"
        Search-FilesForSensitiveData -LookForCredentials:$LookForCredentials -Extensions:$Extensions
    }

    else {
        Search-FilesForSensitiveData -LookForCredentials:$LookForCredentials
    }
}

if ($Searchfiles) {
    
    if (-not $Extensions -or $Extensions.Count -eq 0) {
        
        Write-Error "You must specify -Extensions when using -Searchfiles."
        return
    }

    Write-Color "`n[+] Searching for files with the following extensions: $($Extensions -join ', ')" "Cyan"
    Search-FilesByExtension -Searchfiles -Extensions $Extensions
}

if ($HelpMessage) {
   
    Write-Host @"
PowerEnum - Windows Enumeration Script

Usage:
  .\powerEnum.ps1                    Run with default enumeration
  .\powerEnum.ps1 -LookForCredentials
                                     Search for possible passwords/usernames in common files
  .\powerEnum.ps1 -LookForCredentials -Extensions ".txt,.xml"
                                     Search for credentials in custom file extensions
  .\powerEnum.ps1 -Searchfiles -Extensions ".txt,.xml"
                                     Search for files with specified extensions
  .\powerEnum.ps1 -h / -help        Display this help message

Description:
  PowerEnum is a PowerShell script for privilege escalation enumeration,
  inspired by PEASS-ng and HackTricks.

"@
    exit
}


############################################################
