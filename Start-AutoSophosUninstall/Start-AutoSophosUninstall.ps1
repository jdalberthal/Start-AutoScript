<#
Name              : Start-AutoSophosUninstall
Version           : v1.0.0.0, 01/15/2021
Author            : JD Alberthal
CompanyName       : Rackspace Inc

.SYNOPSIS
Script to force uninstall Sophos

.DESCRIPTION
This script performs the following task:

    Disables Tamper Protection
    Reboots
    Uninstalls Sophos
    Reboots

.OUTPUTS
Files Written to the hard drive are:
    AutoSophosUninstall_Tracking.json    : The script uses this to track its progress
    AutoSophosUninstall_Tracking_Log.txt : This the human readable log with step results and time stamps.

    These are written to the same location as where the script was executed.

.EXAMPLE
<path-to-script>\Start-AutoSophosUninstall.ps1 -AutoLoginUser '.\rack' -AutoLoginPassword 'rackpassword'

.PARAMETER AutoLoginUser
    Only tested with local accounts with Administrator rights.
    Written to the registry and erase at the completion of the script.

.PARAMETER AutoLoginPassword
    Used with AutoLoginUser to auto-login and continue running the script.
    Written to the registry and erase at the completion of the script.
#>

[CmdletBinding()]
Param(

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String[]]$AutoLoginUser,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String[]]$AutoLoginPassword
)

Clear-Host
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CommentBasedHelp', '', Scope = 'Script')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSProvideCommentHelp', '', Scope = 'Script')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope = 'Script')]

#Control Array>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
$Steps = @(
    [ORDERED]@{'Action' = 'DisableTamperProtection'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Set-TamperProtection' }
    [ORDERED]@{'Action' = 'TamperProtectionReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'UninstallSophos'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Uninstall-Sophos' }
    [ORDERED]@{'Action' = 'SophosReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }

)
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#region begin MUST HAVE FUNCTIONS
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
$ProcessTrackingFile = "$PSScriptRoot\AutoSophosUninstall_Tracking.json";
$ProcessLogFile = "$PSScriptRoot\AutoSophosUninstall_Tracking_Log.txt";
#Remove-Item $ProcessTrackingFile
#Remove-Item $ProcessLogFile


function Get-ProcessStatus
{
    #Write-output "Executing Get-ProcessStatus function"

    $Tracking = @{
        'CurrentStep'     = '1'
        'CurrentAction'   = ''
        'RebootInitiated' = 'Not Set'
        'ScriptComplete'  = 'False'
        'ProcessReboot'   = 'Not Set'
        'ExitCode'        = ''
        'Message'         = ''
    }

    $Script:SetJSON = @{
        'Steps'    = $Steps
        'Tracking' = $Tracking
    }

    if (Test-Path -Path $ProcessTrackingFile)
    {
        $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json
        $Script:SetJSON.Steps = $Script:GetJSON.Steps
        $Script:SetJSON.Tracking = $Script:GetJSON.Tracking
    }
    else
    {
        $Script:SetJSON = @{
            'Steps'    = $Steps
            'Tracking' = $Tracking
        }
    }

    $Script:CurrentStepNumber = [int]$Script:SetJSON.Tracking.CurrentStep
    $Script:CurrentStepIndex = ($Script:CurrentStepNumber - 1)
    $SAV = (($Script:SetJSON.Steps[$Script:CurrentStepIndex]).Action)
    $Script:SetJSON.Tracking.CurrentAction = $SAV

    $Script:SetJSON | ConvertTo-Json -Depth 3 | Set-Content $ProcessTrackingFile

    $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json

    $count = 0
    foreach ($stat in $Script:GetJSON.Steps.Status)
    {
        if ($stat -eq 'Started')
        {
            $count++
        }
    }

    if ($count -gt 1)
    {
        $Script:BadExit = $true
        $Script:ExitMessage = "More than one step appears to be in progress."
        $Script:ExitMessage += "`r`nThis should not be happening."
        Start-ScriptCleanup
    }

}

function Test-ScriptCompletion
{
    #Write-output "Executing Test-ScriptCompletion function"

    if ($Script:CurrentStepNumber -gt ($Script:GetJSON.Steps).count)
    {
        $Script:SetJSON.Tracking.ScriptComplete = "True"
        $Script:SetJSON | ConvertTo-Json -Depth 3 | Set-Content $ProcessTrackingFile
        $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json
        ($Script:GetJSON.Steps | Format-Table Action, Status, TimeStamp, Function -auto | Out-String) | Set-Content -Path $ProcessLogFile
        $Script:GetJSON.Tracking.Message | Add-Content -Path $ProcessLogFile
    }

    if (($Script:GetJSON.Tracking.RebootInitiated -eq "True") -and ($Script:GetJSON.Tracking.ScriptComplete -eq "True"))
    {
        Get-RebootStatus
        $Script:SetJSON | ConvertTo-Json -Depth 3 | Set-Content $ProcessTrackingFile

        $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json
        ($Script:GetJSON.Steps | Format-Table Action, Status, TimeStamp, Function -auto | Out-String) | Set-Content -Path $ProcessLogFile
        $Script:GetJSON.Tracking.Message | Add-Content -Path $ProcessLogFile
        $script:ExitMessage = "All steps complete. Exiting script."
        Start-ScriptCleanup
    }
    elseif ($Script:GetJSON.Tracking.ScriptComplete -eq "True")
    {
        $Script:SetJSON | ConvertTo-Json -Depth 3 | Set-Content $ProcessTrackingFile

        $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json
        ($Script:GetJSON.Steps | Format-Table Action, Status, TimeStamp, Function -auto | Out-String) | Set-Content -Path $ProcessLogFile
        $Script:GetJSON.Tracking.Message | Add-Content -Path $ProcessLogFile
        $script:ExitMessage = "All steps complete. Exiting script."
        Start-ScriptCleanup
    }
}

function Test-ProcessStatus
{
    #Write-output "Executing Test-ProcessStatus function"

    if (($Script:GetJSON.Tracking.ExitCode -eq "0") -and ($Script:GetJSON.Steps[$Script:CurrentStepIndex].Status -ne "Skipped"))
    {
        $Script:CurrentStepNumber = ([int]$Script:CurrentStepNumber + 1)
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Completed"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
    }
    elseif ($Script:GetJSON.Steps[$Script:CurrentStepIndex].Status -eq "Skipped")
    {
        $Script:CurrentStepNumber = ([int]$Script:CurrentStepNumber + 1)

    }
    elseif ($Script:GetJSON.Tracking.ExitCode -eq 2)
    {
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Failed/Continued"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
        $Script:CurrentStepNumber = ([int]$Script:CurrentStepNumber + 1)
        #$Script:BadExit = $true
        #$CurrentFunction = $Script:GetJSON.Steps[($Script:CurrentStepIndex)].Function
        #$Script:ExitMessage = "Something went wrong in function: $CurrentFunction"
        #Start-ScriptCleanup
    }
    elseif ($Script:GetJSON.Tracking.ExitCode -eq 1)
    {
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Failed/Exit"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
        $Script:BadExit = $true
        $CurrentFunction = $Script:GetJSON.Steps[($Script:CurrentStepIndex)].Function
        $Script:ExitMessage = "Something went wrong in function: $CurrentFunction"
        Update-JSONProcess
        Start-ScriptCleanup
    }
}

function Start-ExecutingSteps
{
    #Write-output "Executing Start-ExecutingSteps function"

    if ($Script:GetJSON.Tracking.RebootInitiated -eq "True")
    {
        Get-RebootStatus
    }

    Write-Output "Executing function: $($Script:GetJSON.Steps[($Script:CurrentStepIndex)].Function)"

    $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Started"
    $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
    $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
    & $Script:GetJSON.Steps[($Script:CurrentStepIndex)].Function
}

function Update-JSONProcess
{
    #Write-output "Executing Update-JSONProcess function"

    if ($Script:CurrentStepNumber -ge ($Script:GetJSON.Steps).count)
    {
        Test-ScriptCompletion
    }

    if ($Script:SetJSON.Tracking.ProcessReboot -eq "False")
    {
        $Script:SetJSON.Tracking.RebootInitiated = "False"
    }

    $Script:SetJSON.Tracking.CurrentStep = $Script:CurrentStepNumber
    $Script:CurrentStepIndex = ($Script:SetJSON.Tracking.CurrentStep - 1)
    $SAV = (($Script:SetJSON.Steps[$Script:CurrentStepIndex]).Action)
    $Script:SetJSON.Tracking.CurrentAction = $SAV

    $Script:SetJSON | ConvertTo-Json -Depth 3 | Set-Content $ProcessTrackingFile

    $Script:GetJSON = Get-Content $ProcessTrackingFile | ConvertFrom-Json
    ($Script:GetJSON.Steps | Format-Table Action, Status, TimeStamp, Function -auto | Out-String) | Set-Content -Path $ProcessLogFile
    $Script:GetJSON.Tracking.Message | Add-Content -Path $ProcessLogFile
}

function Get-RebootStatus
{

    $RebootAction = $Script:GetJSON.Steps[($Script:CurrentStepIndex)].Action

    #Write-output "Executing Get-RebootStatus function"
    $Events = Get-WinEvent -FilterHashtable @{logname = "System"; id = 1074 } | Select-Object -first 1
    [xml]$Event = $Events[0].ToXml()
    $TheEvent = [Collections.Generic.List[Object]]($Event.Event.EventData.Data)
    $CommentIndex = $TheEvent.FindIndex( { $args[0].'#text' -match $RebootAction } )
    $Script:LastRebootEvent = $TheEvent[$CommentIndex].'#text'
    if ($Script:LastRebootEvent -notmatch $RebootAction)
    {
        $Script:BadExit = $true
        $Script:ExitMessage = "Windows System Event Log does not contain a matching entry for $RebootAction reboot."
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Failed"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
        Update-JSONProcess
        Start-ScriptCleanup
    }
    else
    {

        Write-Output "Windows System Event Log contains a matching entry for $RebootAction reboot."
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Completed"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
        $Script:SetJSON.Tracking.RebootInitiated = "Not Set"
        $Script:SetJSON.Tracking.ProcessReboot = "Not Set"
        $Script:CurrentStepNumber = ([int]$Script:CurrentStepNumber + 1)
        Update-JSONProcess
    }
}

function Restart-Server
{
    #Write-output "Executing Restart-Server function: $($Script:GetJSON.Steps[$Script:CurrentStepIndex].Action)"

    if (($Script:GetJSON.Tracking.ProcessReboot -ne "False") -and ($Script:GetJSON.Tracking.ProcessReboot -ne "True"))
    {
        $Script:BadExit = $true
        $script:ExitMessage = "Reboot preference not set. Exiting Script."
        $Script:SetJSON.Tracking.ProcessReboot = "Not Set"
        Start-ScriptCleanup
    }

    if ($Script:GetJSON.Tracking.ProcessReboot -eq "False")
    {
        Write-Output "Setting reboot status to skipped"
        $Script:SetJSON.Tracking.RebootInitiated = "Not Set"
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Skipped"
        $Script:SetJSON.Tracking.ProcessReboot = "Not Set"
    }
    elseif ($Script:GetJSON.Tracking.ProcessReboot -eq "True")
    {
        $Script:SetJSON.Tracking.RebootInitiated = "True"
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].Status = "Started"
        $time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss tt")
        $Script:SetJSON.Steps[$Script:CurrentStepIndex].TimeStamp = $time
        Update-JSONProcess
        $OSObject = Get-WmiObject -Class Win32_OperatingSystem
        $OSObject.psbase.Scope.Options.EnablePrivileges = $true
        $OSObject.Win32ShutdownTracker(0, ($Script:GetJSON.Steps[$Script:CurrentStepIndex]).Action, 2147614724, 6)
        #$OSObject.Win32ShutdownTracker(0, "Simulated reboot event failure", 2147614724, 6)
        Start-Sleep 60
    }
}

Function Set-RunOnce
{
    #Write-Output "Executing Set-RunOnce function"
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    set-itemproperty $RunOnceKey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -NoExit -executionPolicy bypass ' + $Script)
    return
}

Function Set-AutoLogon
{
    Begin
    {
        #Registry path declaration
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        New-Item 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -ErrorAction SilentlyContinue
        New-ItemProperty 'HKCU:\Console\%SystemRoot%_System32_WindowsPowerShell_v1.0_powershell.exe' -Name FontSize -type DWORD -value 0x000c0000 -ErrorAction SilentlyContinue
    }

    Process
    {

        try
        {
            #setting registry values
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
            Set-ItemProperty $RegPath "DefaultUsername" -Value "$AutoLoginUser" -type String
            Set-ItemProperty $RegPath "DefaultPassword" -Value "$AutoLoginPassword" -type String
            if ($AutoLogonCount)
            {

                Set-ItemProperty $RegPath "AutoLogonCount" -Value "$AutoLogonCount" -type DWord

            }
            else
            {

                Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type DWord

            }
        }

        catch
        {

            Write-Output "An error had occured $Error"

        }
    }

    End
    {

        #End

    }

}

Function Clear-RegValues
{
    Begin
    {
        #Registry path declaration
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $RegROPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

    }

    Process
    {

        try
        {
            #setting registry values
            Set-ItemProperty $RegPath "AutoAdminLogon" -Value "" -type String
            Set-ItemProperty $RegPath "DefaultUsername" -Value "" -type String
            Set-ItemProperty $RegPath "DefaultPassword" -Value "" -type String
            Set-ItemProperty $RegPath "AutoLogonCount" -Value "0" -type DWord
            Set-ItemProperty $RegROPath "NextRun" -Value "" -type String
        }
        catch
        {
            Write-Output "An error had occured $Error"
        }
    }
    End
    {
        #End
    }
}

function Confirm-Credentials
{
    #Write-Output "Executing Confirm-Credentials function"

    if ($script:CurrentStepNumber -eq 1)
    {
        if (($null -eq $AutoLoginUser) -or ($null -eq $AutoLoginPassword))
        {
            #$Script:BadExit = $true
            Write-Output "Full AutoLogin Credentials not provided."
            Write-Output "No-touch automation will not take place."
            write-output " "
            $Script:SetJSON.Tracking.Message = "Full AutoLogin Credentials not provided. No-touch automation will not take place."
            Update-JSONProcess
        }
        else
        {
            $AutoLogonCount = ($Script:GetJSON.Steps).Count
            Set-AutoLogon -AutoLogonCount $AutoLogonCount
        }
    }
    $Script = $PSCommandPath
    Set-RunOnce -Script $Script
}

function Start-ScriptCleanup
{
    #Write-Output "Executing Start-ScriptCleanup function"

    if ($Script:GetJSON.Tracking.ScriptComplete -eq "True")
    {
        Write-Output ""
        Write-Output "All script steps performed. Exiting Script."
        Write-Output ""
        Clear-RegValues
        break
    }

    if ($Script:BadExit -eq $true)
    {
        Write-Output ""
        Write-Output $Script:ExitMessage
        Write-Output ""
        Clear-RegValues
        break
    }
    elseif ($Script:BadExit -eq $False)
    {
        Write-Output ""
        Write-Output $Script:ExitMessage
        Write-Output ""
        Clear-RegValues
        break
    }
    else
    {
        Write-Output ""
        Write-Output "Unknown exit reason"
        Write-Output ""
        Clear-RegValues
        break
    }
}


Function Get-Software
{
    [OutputType('System.Software.Inventory')]
    [Cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]$Computername = $env:COMPUTERNAME
    )
    Begin
    {
    }
    Process
    {
        ForEach ($Computer in  $Computername)
        {
            If (Test-Connection -ComputerName  $Computer -Count  1 -Quiet)
            {
                $Paths = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
                ForEach ($Path in $Paths)
                {
                    Write-Verbose  "Checking Path: $Path"
                    #  Create an instance of the Registry Object and open the HKLM base key
                    Try
                    {
                        $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $Computer, 'Registry64')
                    }
                    Catch
                    {
                        Write-Error $_
                        Continue
                    }
                    #  Drill down into the Uninstall key using the OpenSubKey Method
                    Try
                    {
                        $regkey = $reg.OpenSubKey($Path)
                        # Retrieve an array of string that contain all the subkey names
                        $subkeys = $regkey.GetSubKeyNames()
                        # Open each Subkey and use GetValue Method to return the required  values for each
                        ForEach ($key in $subkeys)
                        {
                            Write-Verbose "Key: $Key"
                            $thisKey = $Path + "\\" + $key
                            Try
                            {
                                $thisSubKey = $reg.OpenSubKey($thisKey)
                                # Prevent Objects with empty DisplayName
                                $DisplayName = $thisSubKey.getValue("DisplayName")
                                If ($DisplayName -AND $DisplayName -notmatch '^Update  for|rollup|^Security Update|^Service Pack|^HotFix')
                                {
                                    $Date = $thisSubKey.GetValue('InstallDate')
                                    If ($Date)
                                    {
                                        Try
                                        {
                                            $Date = [datetime]::ParseExact($Date, 'yyyyMMdd', $Null)
                                        }
                                        Catch
                                        {
                                            Write-Warning "$($Computer): $_ <$($Date)>"
                                            $Date = $Null
                                        }
                                    }
                                    # Create New Object with empty Properties
                                    $Publisher = Try
                                    {
                                        $thisSubKey.GetValue('Publisher').Trim()
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('Publisher')
                                    }
                                    $Version = Try
                                    {
                                        #Some weirdness with trailing [char]0 on some strings
                                        $thisSubKey.GetValue('DisplayVersion').TrimEnd(([char[]](32, 0)))
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('DisplayVersion')
                                    }
                                    $UninstallString = Try
                                    {
                                        $thisSubKey.GetValue('UninstallString').Trim()
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('UninstallString')
                                    }
                                    $InstallLocation = Try
                                    {
                                        $thisSubKey.GetValue('InstallLocation').Trim()
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('InstallLocation')
                                    }
                                    $InstallSource = Try
                                    {
                                        $thisSubKey.GetValue('InstallSource').Trim()
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('InstallSource')
                                    }
                                    $HelpLink = Try
                                    {
                                        $thisSubKey.GetValue('HelpLink').Trim()
                                    }
                                    Catch
                                    {
                                        $thisSubKey.GetValue('HelpLink')
                                    }
                                    $Object = [pscustomobject]@{
                                        Computername    = $Computer
                                        DisplayName     = $DisplayName
                                        Version         = $Version
                                        InstallDate     = $Date
                                        Publisher       = $Publisher
                                        UninstallString = $UninstallString
                                        InstallLocation = $InstallLocation
                                        InstallSource   = $InstallSource
                                        HelpLink        = $thisSubKey.GetValue('HelpLink')
                                        EstimatedSizeMB = [decimal]([math]::Round(($thisSubKey.GetValue('EstimatedSize') * 1024) / 1MB, 2))
                                    }
                                    $Object.pstypenames.insert(0, 'System.Software.Inventory')
                                    Write-Output $Object
                                }
                            }
                            Catch
                            {
                                Write-Warning "$Key : $_"
                            }
                        }
                    }
                    Catch { }
                    $reg.Close()
                }
            }
            Else
            {
                Write-Error  "$($Computer): unable to reach remote system!"
            }
        }
    }
}

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#endregion

#region begin USER FUNCTIONS
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
Function Set-TamperProtection
{
    New-ItemProperty 'HKLM:\SOFTWARE\Wow6432Node\Sophos\SavService\TamperProtection' -Name Enabled -type DWORD -value 0 -ErrorAction SilentlyContinue
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "True"

}

function Uninstall-Sophos
{

    $SophosComponents = Get-Software | Where-Object { $_.DisplayName -like "*Sophos*" }

    if ($SophosComponents)
    {

        #Stop Sophos Services
        $SophosSvcStat = @()
        $SophosServices = @("Sophos Agent",
            "Sophos Anti-Virus",
            "Sophos Anti-Virus status reporter",
            "Sophos AutoUpdate Service",
            "Sophos Message Router",
            "Sophos Web Intelligence Service",
            "Sophos Web Control Service"
            "Sophos Web Filter",
            "Sophos System Protection Service")

        foreach ($SophosService in $SophosServices)
        {
            Stop-Service -Displayname $SophosService -Force -ErrorAction SilentlyContinue
        }

        foreach ($SophosService in $SophosServices)
        {
            $SophosSvcChk = Get-Service -Displayname $SophosService -ErrorAction SilentlyContinue
            if ($SophosSvcChk.status -eq "Running") { $SophosSvcStat += $SophosSvcChk }
        }

        if ($SophosSvcStat.count -gt 0)
        {
            Write-Output "Not all Sophos Services could be stopped."
            $SophosSvcStat
        }
        else
        {
            Write-Output "All Sophos Services stopped."
        }
        #Kill Sophos Proccesses
        $SophosProcStat = @()
        $SophosProcs = @("ALMon",
            "ALsvc",
            "ManagementAgentNT",
            "RouterNT",
            "SAVAdminService",
            "SavService",
            "ssp"
            "swc_service",
            "swi_fc",
            "swi_filter",
            "swi_service")

        foreach ($SophosProc in $SophosProcs)
        {
            Stop-Process -Name $SophosProc -Force -ErrorAction SilentlyContinue
        }

        foreach ($SophosProc in $SophosProcs)
        {
            $SophosProcChk = Get-Process -Name $SophosProc -ErrorAction SilentlyContinue
            if ($SophosProcChk) { $SophosProcStat += $SophosProcChk.name }
        }

        if ($SophosProcStat.count -gt 0)
        {
            Write-Output "Not all Sophos Processes could be stopped."
            $SophosProcStat
        }
        else
        {
            Write-Output "All Sophos Processes stopped."
        }

        #$SophosComponents = Get-Software | Where-Object { $_.DisplayName -like "*Sophos*" }

        [array]$Uninstallorder = @(
            #"Patch Agent",
            #"Compliance Agent",
            #"Network Threat Protection",
            "Sophos System Protection",
            #"Client Firewall",
            "Sophos Anti-Virus",
            #"Exploit Prevention"
            "Sophos Remote Management System",
            #"Management Communication System",
            "Sophos AutoUpdate",
            "Sophos Endpoint Defense"
        )

        $ErrorMsg = @()

        $SoftwareToUninstall = $SophosComponents | Where-Object { $_.DisplayName -match ($Uninstallorder -join '|') }

        $MsiExecPattern = (
            "msiexec(.exe)?" +
            ".*" +
            "/X" +
            "\s*" +
            "(?<Guid>{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}})"
        )

        ForEach ($Software in $SoftwareToUninstall)
        {
            if ($Software.UninstallString -match $MsiExecPattern)
            {
                #get a name without whitespace for the log file path
                #$Name = $Software.DisplayName.Replace(" ", "_")

                #generate the msi params
                $Params = @(
                    "/X $($Matches.Guid)"
                    "/qn"
                    "REBOOT=SUPPRESS"
                    #"/L*v C:\rs-pkgs\Sophos\Uninstall_$Name`_Log.txt"
                )

                $Result = Start-Process msiexec.exe -ArgumentList $Params -Wait -PassThru

                #switch on the error code, anything but 0 or 3010 is bad
                switch ($Result.ExitCode)
                {
                    "3010" { $UninstallReboot = $true ; Continue }
                    "0" { $Success = $true ; Continue }
                    Default { $ErrorMsg += "$Name failed to uninstall. Exit code: $($Result.ExitCode)" ; Continue }
                }
            }
            else
            {
                $SoftwareUninstallString = ($Software.UninstallString).Replace('"', "")
                & $SoftwareUninstallString
            }
        }

        #if we have error messages, join them into a nice string
        if ($ErrorMsg)
        {
            $output.Result = "Errors: $($ErrorMsg -join ",")"
            $Script:SetJSON.Tracking.ExitCode = 2
            $Script:SetJSON.Tracking.ProcessReboot = "True"
            Return
        }
        else
        {
            Write-Output "Sophos Uninstalled"
            write-output ""
            $Script:SetJSON.Tracking.ExitCode = 0
            $Script:SetJSON.Tracking.ProcessReboot = "True"
        }
        #if we got 3010 exit code, set the reboot flag
        If ($UninstallReboot)
        {
            $Script:SetJSON.Tracking.ExitCode = 0
            $Script:SetJSON.Tracking.ProcessReboot = "True"
        }
    }
    else
    {
        Write-Output "Sophos not installed"
        write-output ""
        $Script:SetJSON.Tracking.ExitCode = 0
        $Script:SetJSON.Tracking.ProcessReboot = "False"
    }
    #remove-item "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Sophos" -Recurse -ErrorAction SilentlyContinue
    #remove-item "C:\ProgramData\Sophos" -Recurse -ErrorAction SilentlyContinue
    #remove-item "C:\Program Files (x86)\Sophos" -Recurse -ErrorAction SilentlyContinue
}

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#endregion


#region begin MUST HAVE PROCESS LOOP
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
Get-ProcessStatus
Test-ScriptCompletion
Confirm-Credentials

for ($step = 1; $step -le ($Script:GetJSON.Steps).Count; $step++)
{
    Start-ExecutingSteps
    Update-JSONProcess
    Test-ProcessStatus
    Update-JSONProcess
}
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
#endregion
