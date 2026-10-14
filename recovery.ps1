```powershell
#requires -Version 5.1

<#
.SYNOPSIS
    Read-only forensic inventory of files on a NAS share.

.DESCRIPTION
    Recursively scans files, calculates SHA-256 hashes,
    and exports inventory and error reports to a chosen folder.

    Uses the current Windows authentication context.
    Does not request or store NAS credentials.

.OUTPUTS
    forensic_<dataset>_<timestamp>.csv
    forensic_errors_<dataset>_<timestamp>.csv
#>

$ErrorActionPreference = "Stop"

# ============================================================
# 1. BANNER
# ============================================================

Clear-Host

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "          FORENSIC FILE INVENTORY TOOL" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Recursively inventories files on a NAS share."
Write-Host "Calculates SHA-256 hashes and exports CSV reports."
Write-Host "Source files will not intentionally be modified."
Write-Host ""

# ============================================================
# 2. GET NAS PATH
# ============================================================

$RootInput = Read-Host "Enter the NAS folder path to scan"

if ([string]::IsNullOrWhiteSpace($RootInput)) {
    Write-Host "ERROR: No NAS path supplied." -ForegroundColor Red
    return
}

$RootPath = $RootInput.Trim().Trim('"')

try {
    $RootItem = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop

    if (-not $RootItem.PSIsContainer) {
        throw "The specified path is not a directory."
    }

    $RootPath = $RootItem.FullName.TrimEnd('\', '/')
}
catch {
    Write-Host "ERROR: Cannot access the specified NAS folder." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    return
}

# ============================================================
# 3. GET DATASET LABEL
# ============================================================

$DatasetInput = Read-Host "Enter a dataset label (e.g. before_recovered)"

if ([string]::IsNullOrWhiteSpace($DatasetInput)) {
    $DatasetInput = "dataset"
}

$DatasetName = $DatasetInput -replace '[^\w.-]', '_'

# ============================================================
# 4. GET CSV OUTPUT FOLDER
# ============================================================

$DefaultOutput = Join-Path $env:USERPROFILE "Downloads"

$OutputInput = Read-Host "Enter CSV output folder path (press Enter for $DefaultOutput)"

if ([string]::IsNullOrWhiteSpace($OutputInput)) {
    $OutputPath = $DefaultOutput
}
else {
    $OutputPath = $OutputInput.Trim().Trim('"')
}

try {
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        New-Item -ItemType Directory -Path $OutputPath -Force `
            -ErrorAction Stop | Out-Null
    }

    $OutputPath = (Get-Item -LiteralPath $OutputPath -ErrorAction Stop).FullName
}
catch {
    Write-Host "ERROR: Cannot access or create the output folder." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    return
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$InventoryPath = Join-Path $OutputPath (
    "forensic_{0}_{1}.csv" -f $DatasetName, $Timestamp
)

$ErrorsPath = Join-Path $OutputPath (
    "forensic_errors_{0}_{1}.csv" -f $DatasetName, $Timestamp
)

# ============================================================
# 5. INITIALIZE
# ============================================================

$Inventory = [System.Collections.Generic.List[object]]::new()
$Errors = [System.Collections.Generic.List[object]]::new()

$DirectoriesScanned = 0
$FilesDiscovered = 0
$FilesHashed = 0
$HashFailures = 0
$EnumerationFailures = 0
$SkippedReparseDirectories = 0

$StartTime = Get-Date

$DirectoryStack = [System.Collections.Generic.Stack[string]]::new()
$DirectoryStack.Push($RootPath)

$Prefix = $RootPath.TrimEnd('\', '/') + '\'

Write-Host ""
Write-Host "Dataset : $DatasetName" -ForegroundColor Gray
Write-Host "Root    : $RootPath" -ForegroundColor Gray
Write-Host "Reports : $OutputPath" -ForegroundColor Gray
Write-Host ""
Write-Host "Starting recursive scan..." -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 6. ENUMERATE DIRECTORIES AND HASH FILES
# ============================================================

while ($DirectoryStack.Count -gt 0) {

    $CurrentDirectory = $DirectoryStack.Pop()
    $DirectoriesScanned++

    try {
        $Items = @(
            Get-ChildItem -LiteralPath $CurrentDirectory `
                -Force -ErrorAction Stop
        )
    }
    catch {
        $EnumerationFailures++

        $Errors.Add([PSCustomObject]@{
            ErrorType = "DirectoryEnumerationError"
            Path      = $CurrentDirectory
            Details   = $_.Exception.Message
        })

        continue
    }

    foreach ($Item in $Items) {

        if ($Item.PSIsContainer) {

            # Do not traverse directory junctions or symbolic links.
            if (($Item.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0) {

                $SkippedReparseDirectories++

                $Errors.Add([PSCustomObject]@{
                    ErrorType = "DirectorySkippedReparsePoint"
                    Path      = $Item.FullName
                    Details   = "Directory link/junction was not traversed."
                })

                continue
            }

            $DirectoryStack.Push($Item.FullName)
            continue
        }

        $FilesDiscovered++

        $RelativePath = $Item.FullName.Substring($Prefix.Length)
        $Hash = $null
        $HashStatus = "OK"
        $HashError = $null

        try {
            $Hash = (
                Get-FileHash -LiteralPath $Item.FullName `
                    -Algorithm SHA256 -ErrorAction Stop
            ).Hash

            $FilesHashed++
        }
        catch {
            $HashStatus = "HASH_ERROR"
            $HashError = $_.Exception.Message
            $HashFailures++

            $Errors.Add([PSCustomObject]@{
                ErrorType = "FileHashError"
                Path      = $Item.FullName
                Details   = $HashError
            })
        }

        $Inventory.Add([PSCustomObject]@{
            FullPath         = $Item.FullName
            RelativePath     = $RelativePath
            FileName         = $Item.Name
            Extension        = $Item.Extension
            SizeBytes        = $Item.Length
            LastWriteTimeUtc = $Item.LastWriteTimeUtc.ToString("o")
            SHA256           = $Hash
            HashStatus       = $HashStatus
            Error            = $HashError
        })

        if (($FilesDiscovered % 25) -eq 0) {
            Write-Progress `
                -Activity "Forensic inventory: $DatasetName" `
                -Status (
                    "Directories: {0} | Files discovered: {1} | Files hashed: {2}" -f
                    $DirectoriesScanned, $FilesDiscovered, $FilesHashed
                )
        }
    }
}

Write-Progress -Activity "Forensic inventory: $DatasetName" -Completed

# ============================================================
# 7. EXPORT CSV REPORTS
# ============================================================

Write-Host ""
Write-Host "Exporting reports..." -ForegroundColor Cyan

try {
    $Inventory | Export-Csv `
        -LiteralPath $InventoryPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -ErrorAction Stop

    $Errors | Export-Csv `
        -LiteralPath $ErrorsPath `
        -NoTypeInformation `
        -Encoding UTF8 `
        -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Report export failed." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    return
}

# ============================================================
# 8. SUMMARY
# ============================================================

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "                   SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

Write-Host ("Dataset:                    {0}" -f $DatasetName)
Write-Host ("Directories enumerated:     {0}" -f $DirectoriesScanned)
Write-Host ("Files discovered:           {0}" -f $FilesDiscovered)
Write-Host ("Files successfully hashed:  {0}" -f $FilesHashed)
Write-Host ("Hash failures:              {0}" -f $HashFailures)
Write-Host ("Enumeration failures:       {0}" -f $EnumerationFailures)
Write-Host ("Skipped linked directories: {0}" -f $SkippedReparseDirectories)
Write-Host ("Duration:                   {0}" -f $Duration)
Write-Host ""

Write-Host "Inventory CSV:" -ForegroundColor Green
Write-Host $InventoryPath

Write-Host ""
Write-Host "Error report CSV:" -ForegroundColor Yellow
Write-Host $ErrorsPath

if ($HashFailures -gt 0 -or
    $EnumerationFailures -gt 0 -or
    $SkippedReparseDirectories -gt 0) {

    Write-Host ""
    Write-Host "WARNING: Review the error report before comparing inventories." `
        -ForegroundColor Yellow

    Write-Host "The scan may not represent every file under the root."
}
else {
    Write-Host ""
    Write-Host "No file hashing or directory enumeration errors were recorded." `
        -ForegroundColor Green
}

Write-Host ""
Write-Host "The source dataset was not intentionally modified."
Write-Host ""
```
