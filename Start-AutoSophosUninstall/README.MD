This script performs the following task:

    Disables Tamper Protection
    Reboots
    Uninstalls Sophos
    Reboots

<path-to-script>\Start-AutoSophosUninstall.ps1 -AutoLoginUser '.\rack' -AutoLoginPassword 'rackpassword'

The credentials will allow the script to perform all its step without interaction.

Without credentials you will have to login after each reboot.
