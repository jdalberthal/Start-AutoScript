<#

v1.0.0.0

.SYNOPSIS
Script to process custom configuration steps in specified order for a server

.DESCRIPTION
1. This script uses an array to define the order of user provided functions to process.

2. It uses 2 variables to control the flow of user provided functions.
    $Script:SetJSON.Tracking.ExitCode
    $Script:SetJSON.Tracking.ProcessReboot

3. There are 4 script parameters. None are mandatory.
    AutoLoginUser
    AutoLoginPassword
    DomainUser
    DomainPassword
    Domain

4. There are also 2 regions that must remain as written.
    #region begin MUST HAVE PROCESS LOOP
    #region begin MUST HAVE FUNCTIONS

5. The 3rd region, #region begin USER FUNCTIONS, is for user provided functions.

6. Files Written to the hard drive are:
    AutoScript_Tracking.json    : The script uses this to track its progress
    AutoScript_Tracking_Log.txt : This the human readable log with step results and time stamps.

    These are written to the same location as where the script was ran.

.EXAMPLE
This is a sample of the control array that includes the built-in 'Restart-Server' function:
    $Steps = @(
        [ORDERED]@{'Action' = 'CheckUpdates'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Get-PendingUpdates' }
        [ORDERED]@{'Action' = 'UpdatesReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
        )

        The only thing you need to define is the 'Action' name and the 'Function' to call.

    How the Action/Function completes is controlled by your use of the following variable in your function.

    You can set the a function ExitCode to what you want, BUT, the script uses these three:
        $Script:SetJSON.Tracking.ExitCode = 0 : This tells the script to mark that step as completed and to continue processing
        $Script:SetJSON.Tracking.ExitCode = 1 : This tells the script to mark that step as Failed/Exit and halts the script
        $Script:SetJSON.Tracking.ExitCode = 2 : This tells the script to mark that step as Failed/Continued and to continue processing

    If you include the use of the built-in 'Restart-Server' function, you can also define in your function whether or not
    to process the reboot depending on the outcome of your function. This is separate from the ExitCode.
    If you call the 'Restart-Server' function after one of yours, the following MUST be set or the script will halt.
        $Script:SetJSON.Tracking.ProcessReboot = "False" or
        $Script:SetJSON.Tracking.ProcessReboot = "True"

    So using the above sample array, here are some examples of how the 'Get-PendingUpdates' and 'Restart-Server' could flow based on your use of
        $Script:SetJSON.Tracking.ExitCode
        $Script:SetJSON.Tracking.ProcessReboot

        1. 'Get-PendingUpdates' fails due to no communications with update server.
            You could set the ExitCode to '$Script:SetJSON.Tracking.ExitCode = 1' for that result so the script halts so you can check the communication issue.
            $Script:SetJSON.Tracking.ProcessReboot is not needed because the script will have quit.

        2. 'Get-PendingUpdates' fails due to any reason, but you don't consider it a hard stop.
            You could set the ExitCode to '$Script:SetJSON.Tracking.ExitCode = 2' for that result so the rest of steps continue to process.
            Because the 'Restart-Server' follows 'Get-PendingUpdates', you have to set $Script:SetJSON.Tracking.ProcessReboot.
            You can set '$Script:SetJSON.Tracking.ProcessReboot = "False"' for this failure so the unneeded reboot isn't processed.

        3. 'Get-PendingUpdates' performs as designed so you can set the two variables as such so the server reboots and continues processing steps.
            $Script:SetJSON.Tracking.ExitCode = 0
            $Script:SetJSON.Tracking.ProcessReboot = "True"

        4. You can supply -DomainUser, -DomainPassword, and -Domain at the command line that will create a System.Management.Automation.PSCredential
            object that can be used in a domain join. 
            If either parameter is not supplied, $DomainCredentials will be forces to $null.
            You can then check for $null in your domain join function to determine whether to process or not.

.PARAMETERS
        AutoLoginUser       : Used to auto-login and continue running the script via the registry
        AutoLoginPassword   : Used to auto-login and continue running the script via the registry
        DomainUser          : Separate credentials to perform a domain join.
        DomainPassword      : Separate credentials to perform a domain join.
        Domain              : Domain to pass to your domain join function if you have one

#>

[CmdletBinding()]
Param(

    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String[]]$AutoLoginUser,

    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String[]]$AutoLoginPassword,

    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$DomainUser,

    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$DomainPassword,

    [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [String]$Domain

)

Clear-Host
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CommentBasedHelp', '', Scope = 'Function')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSProvideCommentHelp', '', Scope = 'Function')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Scope = 'Function')]

#Control Array==========================================================================================
#=======================================================================================================
$Steps = @(
    [ORDERED]@{'Action' = 'CheckUpdates'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Get-PendingUpdates' }
    [ORDERED]@{'Action' = 'UpdatesReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'UninstallSophos'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Uninstall-Sophos' }
    [ORDERED]@{'Action' = 'SophosReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'RenameServer'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'rename-server' }
    [ORDERED]@{'Action' = 'RenameReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'InstallSCCM'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Install-SCCM' }
    [ORDERED]@{'Action' = 'SCCMReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'InstallSymantec'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Install-Symantec' }
    [ORDERED]@{'Action' = 'SymantecReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'InstallBigFix'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Install-BigFix' }
    [ORDERED]@{'Action' = 'BigFixReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
    [ORDERED]@{'Action' = 'JoinDomain'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Join-Domain' }
    [ORDERED]@{'Action' = 'DomainReboot'; 'Status' = 'NotStarted' ; 'TimeStamp' = '00/00/00' ; 'Function' = 'Restart-Server' }
)
#=======================================================================================================
#=======================================================================================================

#region begin MUST HAVE FUNCTIONS
#=======================================================================================================
#=======================================================================================================
$ProcessTrackingFile = "$PSScriptRoot\AutoScript_Tracking.json";
$ProcessLogFile = "$PSScriptRoot\AutoScript_Tracking_Log.txt";
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

function Get-DomainInfo
{
    begin
    {
        #Write-Host "Executing Get-DomainInfo function"
        Write-Verbose "[$(Get-Date)] Begin :: $($MyInvocation.MyCommand)"
        Write-Verbose "[$(Get-Date)] List of Parameters :: $($PSBoundParameters.GetEnumerator() | Out-String)"
    }
    process
    {
        if (([string]::IsNullOrEmpty($DomainUser)) -or ([string]::IsNullOrEmpty($DomainPassword)) -or ([string]::IsNullOrEmpty($Domain)))
        {
            $DomainCredentialsSec = $null
        }
        else
        {
            $PasswordSec = ($DomainPassword | ConvertTo-SecureString -asPlainText -Force)
            $DomainCredentialsSec = New-Object System.Management.Automation.PSCredential($DomainUser, $PasswordSec)
        }

        return $DomainCredentialsSec #| Out-Null

    }
    end
    {
        Write-Verbose "[$(Get-Date)] End   :: $($MyInvocation.MyCommand)"
    }
}

#=======================================================================================================
#=======================================================================================================
#endregion

#region begin USER FUNCTIONS
#=======================================================================================================
#=======================================================================================================
function Get-PendingUpdates
{
    #Write-output "Executing Get-PendingUpdates function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"

}
function Uninstall-Sophos
{
    #Write-output "Executing Uninstall-Sophos function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"
}
function rename-server
{
    #Write-output "Executing rename-server function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"
}
function Install-SCCM
{
    #Write-output "Executing Install-SCCM function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"
}
function Install-Symantec
{
    #Write-output "Executing Install-Symantec function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"
}
function Install-BigFix
{
    #Write-output "Executing Install-BigFix function"
    #sleep 5
    $Script:SetJSON.Tracking.ExitCode = 0
    $Script:SetJSON.Tracking.ProcessReboot = "False"
}
function Join-Domain
{
    #Write-output "Executing Join-Domain function"
    #sleep 5
    if ($null -ne $DomainCredentials)
    {
        $Script:SetJSON.Tracking.ExitCode = 0
        $Script:SetJSON.Tracking.ProcessReboot = "False"
    }
    else
    {
        $Script:SetJSON.Tracking.ExitCode = 0
        $Script:SetJSON.Tracking.ProcessReboot = "False"
    }
}
#=======================================================================================================
#=======================================================================================================
#endregion


#region begin MUST HAVE PROCESS LOOP
#=======================================================================================================
#=======================================================================================================
Get-ProcessStatus
Test-ScriptCompletion
Confirm-Credentials
$DomainCredentials = Get-DomainInfo #-DomainUser $DomainUser -DomainPassword $DomainPassword
Write-output "Domain credentials is null: ($($null -eq $DomainCredentials))"

for ($step = 1; $step -le ($Script:GetJSON.Steps).Count; $step++)
{
    Start-ExecutingSteps
    Update-JSONProcess
    Test-ProcessStatus
    Update-JSONProcess
}
#=======================================================================================================
#=======================================================================================================
#endregion
