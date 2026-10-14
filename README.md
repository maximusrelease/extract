# extract

step 1:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force


step 2:

$Url="https://raw.githubusercontent.com/maximusrelease/extract/refs/heads/main/forensic.ps1"; $Response=Invoke-WebRequest -Uri $Url -ErrorAction Stop; $ScriptText=$Response.Content; $ScriptBlock=[scriptblock]::Create($ScriptText); & $ScriptBlock
