# extract

step 1:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force


step 2:

$Url="https://raw.githubusercontent.com/USERNAME/REPOSITORY/BRANCH/forensic.ps1"; $Response=Invoke-WebRequest -Uri $Url -ErrorAction Stop; $ScriptText=$Response.Content; $ScriptBlock=[scriptblock]::Create($ScriptText); & $ScriptBlock
