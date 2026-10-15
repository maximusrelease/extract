```powershell
#requires -Version 5.1

$ErrorActionPreference = "Stop"

Clear-Host
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "          RECOVERY FILE COPY TOOL" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# 1. GET CSV PATH
# ============================================================

$CsvInput = Read-Host "Enter the full path of Extra.csv"

if ([string]::IsNullOrWhiteSpace($CsvInput)) {
    Write-Host "ERROR: No CSV path supplied." -ForegroundColor Red
    return
}

$CsvPath = $CsvInput.Trim().Trim('"')

try {
    if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
        throw "CSV file not found."
    }

    $Rows = @(Import-Csv -LiteralPath $CsvPath -ErrorAction Stop)

    if ($Rows.Count -eq 0) {
        throw "The CSV contains no data rows."
    }

    $RequiredColumns = @(
        "FullPath",
        "RelativePath",
        "SHA256",
        "HashStatus"
    )

    foreach ($Column in $RequiredColumns) {
        if ($Rows[0].PSObject.Properties.Name -notcontains $Column) {
            throw "Required CSV column missing: $Column"
        }
    }
}
catch {
    Write-Host "ERROR: Could not read the CSV." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    return
}

# ============================================================
# 2. GET DESTINATION NAS FOLDER
# ============================================================

$DestInput = Read-Host "Enter destination NAS folder path"

if ([string]::IsNullOrWhiteSpace($DestInput)) {
    Write-Host "ERROR: No destination path supplied." -ForegroundColor Red
    return
}

$DestinationRoot = $DestInput.Trim().Trim('"').TrimEnd('\', '/')

try {
    if (-not (Test-Path -LiteralPath $DestinationRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $DestinationRoot `
            -Force -ErrorAction Stop | Out-Null
    }

    $DestinationRoot = (
        Get-Item -LiteralPath $DestinationRoot -ErrorAction Stop
    ).FullName.TrimEnd('\', '/')
}
catch {
    Write-Host "ERROR: Cannot access or create destination folder." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    return
}

# ============================================================
# 3. CONFIRM OPERATION
# ============================================================

$EligibleCount = @(
    $Rows | Where-Object {
        $_.HashStatus -eq "OK" -and
        $_.SHA256 -match '^[A-Fa-f0-9]{64}$' -and
        -not [string]::IsNullOrWhiteSpace($_.FullPath) -and
        -not [string]::IsNullOrWhiteSpace($_.RelativePath)
    }
).Count

Write-Host ""
Write-Host "CSV rows       : $($Rows.Count)"
Write-Host "Eligible files : $EligibleCount"
Write-Host "Destination    : $DestinationRoot"
Write-Host ""
Write-Host "Existing destination files will NOT be overwritten."
Write-Host "Copied files will be verified using SHA-256."
Write-Host ""

$Confirm = Read-Host "Type COPY to begin"

if ($Confirm -cne "COPY") {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    return
}

# ============================================================
# 4. COPY AND VERIFY
# ============================================================

$Copied = 0
$Failed = 0
$Skipped = 0
$Verified = 0
$Processed = 0

$Total = $Rows.Count

foreach ($Row in $Rows) {

    $Processed++

    Write-Progress `
        -Activity "Copying and verifying recovery files" `
        -Status "Processed $Processed of $Total | Copied: $Copied | Failed: $Failed | Skipped: $Skipped" `
        -PercentComplete ([int](100 * $Processed / [Math]::Max(1, $Total)))

    # Accept only entries with valid recorded SHA-256 hashes.
    if (
        $Row.HashStatus -ne "OK" -or
        $Row.SHA256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        [string]::IsNullOrWhiteSpace($Row.FullPath) -or
        [string]::IsNullOrWhiteSpace($Row.RelativePath)
    ) {
        $Skipped++
        Write-Host "[SKIP] Invalid path or hash: $($Row.FileName)" -ForegroundColor Yellow
        continue
    }

    $SourcePath = $Row.FullPath.Trim()
    $RelativePath = $Row.RelativePath.Trim()

    # Reject rooted paths and traversal outside the destination.
    if (
        [System.IO.Path]::IsPathRooted($RelativePath) -or
        $RelativePath -match '(^|[\\/])\.\.([\\/]|$)'
    ) {
        $Skipped++
        Write-Host "[SKIP] Unsafe relative path: $RelativePath" -ForegroundColor Yellow
        continue
    }

    try {
        if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
            throw "Source file does not exist or is inaccessible."
        }

        $DestinationPath = Join-Path $DestinationRoot $RelativePath

        $DestinationFull = [System.IO.Path]::GetFullPath($DestinationPath)
        $RootFull = [System.IO.Path]::GetFullPath(
            $DestinationRoot + [System.IO.Path]::DirectorySeparatorChar
        )

        if (-not $DestinationFull.StartsWith(
            $RootFull,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Destination path escapes the selected folder."
        }

        # Never overwrite existing files.
        if (Test-Path -LiteralPath $DestinationFull) {
            $Skipped++
            Write-Host "[SKIP] Destination already exists: $RelativePath" -ForegroundColor Yellow
            continue
        }

        $ParentFolder = Split-Path -Parent $DestinationFull

        if (-not (Test-Path -LiteralPath $ParentFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $ParentFolder `
                -Force -ErrorAction Stop | Out-Null
        }

        # Copy directly from the source to the NAS destination.
        Copy-Item -LiteralPath $SourcePath `
            -Destination $DestinationFull `
            -ErrorAction Stop

        # Verify the copied file against the CSV's recorded hash.
        $DestinationHash = (
            Get-FileHash -LiteralPath $DestinationFull `
                -Algorithm SHA256 -ErrorAction Stop
        ).Hash

        if ($DestinationHash -ine $Row.SHA256.Trim()) {
            throw "SHA-256 mismatch. Copied file is not verified."
        }

        $Copied++
        $Verified++

        Write-Host "[VERIFIED] $RelativePath" -ForegroundColor Green
    }
    catch {
        $Failed++
        Write-Host "[FAILED] $RelativePath" -ForegroundColor Red
        Write-Host "         $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Progress -Activity "Copying and verifying recovery files" -Completed

# ============================================================
# 5. SUMMARY
# ============================================================

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "                 COPY COMPLETE" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "CSV rows processed : $Total"
Write-Host "Copied and verified: $Verified" -ForegroundColor Green
Write-Host "Failed             : $Failed" -ForegroundColor Red
Write-Host "Skipped            : $Skipped" -ForegroundColor Yellow
Write-Host ""
Write-Host "Destination: $DestinationRoot"
Write-Host ""
Write-Host "No local report file was created."
Write-Host "Review any FAILED entries above before relying on the results."
```
