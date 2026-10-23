# Collects and outputs to file users and user groups + their permissions

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Rerun as an administrator."
    exit
}

# Dump User List
Write-Output "Dumping User List..."
Get-LocalUser | Format-Table Name, Enabled, LastLogon, Description -AutoSize > UserList.txt
Write-Output "User list dumped to UserList.txt"
Get-Content UserList.txt

# Dump User Privileges
Write-Output "Dumping User Privileges..."
Get-LocalUser | ForEach-Object {
    $user = $_.Name
    $privileges = net user $user | Select-String "Privilege"
    Write-Output "User: $user"
    Write-Output $privileges
    Write-Output ""
} > UserPrivileges.txt
Write-Output "User privileges dumped to UserPrivileges.txt"

# Dump Groups
Write-Output "Dumping Groups..."
Get-LocalGroup | Format-Table Name, Description -AutoSize > GroupList.txt
Write-Output "Group list dumped to GroupList.txt"

# Dump Group Privileges
Write-Output "Dumping Group Privileges..."
Get-LocalGroup | ForEach-Object {
    $group = $_.Name
    $members = Get-LocalGroupMember -Group $group | Select-Object Name, ObjectClass
    Write-Output "Group: $group"
    Write-Output $members
    Write-Output ""
} > GroupPrivileges.txt
Write-Output "Group privileges dumped to GroupPrivileges.txt"
Get-Content GroupPrivileges.txt

Write-Output "Files generated for review"
