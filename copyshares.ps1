<#
.SYNOPSIS
    Resumable NAS -> local downloader driven by an audit CSV.

.DESCRIPTION
    Prompts for:
      1. NAS folder path   (UNC like \\192.168.3.50\cyber-dfir, or a mapped drive like Z:\)
      2. Output folder     (where the files are copied to)
      3. CSV file          (must contain a FullPath column; ExpectedSizeBytes and
                            ExpectedSHA256 are used for verification when present)

    Files are copied ONE AT A TIME (the next copy only starts after the previous one
    has finished and been verified). Each file is written to "<name>.part" first and
    only renamed to its real name once size + SHA256 are verified, so a half-copied
    file is never mistaken for a finished one.

    Progress is logged in the OUTPUT folder:
      _download_state.csv  - one row per attempt (OK / FAILED / MISSING / HASH_MISMATCH)
      _download_log.txt    - human-readable log
    Stop any time with Ctrl+C. Run it again with the SAME output folder and it skips
    everything already marked OK (and still present on disk with the right size) and
    carries on from the first file that is not done.

    Run in memory:
      irm https://raw.githubusercontent.com/<user>/<repo>/main/Download-NasFiles.ps1 | iex
#>

& {
$ErrorActionPreference = 'Stop'

# ------------------------------ settings ------------------------------
$BufferSizeBytes   = 4MB     # copy buffer
$MaxRetries        = 3       # attempts per file before it is marked FAILED
$RetryDelaySeconds = 5       # wait between attempts
$VerifyHash        = $true   # verify SHA256 from the CSV while copying (no second read)

$ctx = @{
    LogFile    = $null
    StateFile  = $null
    SrcOffset  = $null
    BytesDone  = [long]0
    TotalBytes = [long]0
}

# ------------------------------ helpers -------------------------------
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $color = 'Gray'
    switch ($Level) {
        'OK'    { $color = 'Green' }
        'WARN'  { $color = 'Yellow' }
        'ERROR' { $color = 'Red' }
        'HEAD'  { $color = 'Cyan' }
    }
    Write-Host $Message -ForegroundColor $color
    if ($ctx.LogFile) {
        try {
            $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
            Add-Content -LiteralPath $ctx.LogFile -Value $line -Encoding UTF8
        } catch { }
    }
}

function Clean-Input([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Trim().Trim('"').Trim("'").Trim()
}

function Confirm-Yes([string]$Prompt) {
    $a = Read-Host "$Prompt (y/N)"
    return ($a -match '^(y|yes)$')
}

function Read-ExistingPath([string]$Prompt, [string]$Type) {
    while ($true) {
        $p = Clean-Input (Read-Host $Prompt)
        if ($p -match '^[A-Za-z]:$') { $p = $p + '\' }
        if ($p -and (Test-Path -LiteralPath $p -PathType $Type)) { return $p }
        Write-Host "  Not found / not reachable: '$p'  - try again." -ForegroundColor Yellow
    }
}

function Format-Size([double]$b) {
    if     ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    elseif ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    elseif ($b -ge 1KB) { return ('{0:N1} KB' -f ($b / 1KB)) }
    else                { return ('{0:N0} B'  -f $b) }
}

# \\?\ prefix = bypass the 260-char limit and keep odd names (emoji, trailing spaces) intact
function ConvertTo-LongPath([string]$p) {
    if ($p.StartsWith('\\?\')) { return $p }
    if ($p.StartsWith('\\'))   { return '\\?\UNC\' + $p.Substring(2) }
    return '\\?\' + $p
}

function Test-FileLP([string]$p) {
    try { return [System.IO.File]::Exists((ConvertTo-LongPath $p)) } catch { return $false }
}

function Get-Segments([string]$p) {
    return @($p -split '\\' | Where-Object { $_ -ne '' })
}

# Where the file goes under the output folder: FullPath minus "\\server\share\" (or "X:\")
function Get-DestRelative($row) {
    $full = [string]$row.FullPath
    if     ($full -match '^\\\\[^\\]+\\[^\\]+\\(.+)$') { $rel = $Matches[1] }
    elseif ($full -match '^[A-Za-z]:\\(.+)$')          { $rel = $Matches[1] }
    elseif ($row.PSObject.Properties['RelativePath'] -and $row.RelativePath) { $rel = [string]$row.RelativePath }
    else                                                { $rel = [string]$row.FileName }
    return ($rel -replace '/', '\').TrimStart('\')
}

# Re-bases the CSV path onto the NAS folder the user typed. Tries dropping 0,1,2.. leading
# segments of the CSV path until the file is found, and remembers the offset that worked.
function Resolve-Source([string]$full, [string]$nasRoot) {
    $seg  = Get-Segments $full
    $max  = [Math]::Min(6, $seg.Count - 1)
    $base = $nasRoot.TrimEnd('\')
    $order = New-Object System.Collections.Generic.List[int]
    if ($null -ne $ctx.SrcOffset) { $order.Add([int]$ctx.SrcOffset) }
    for ($k = 0; $k -le $max; $k++) {
        if (($null -eq $ctx.SrcOffset) -or ($k -ne $ctx.SrcOffset)) { $order.Add($k) }
    }
    foreach ($k in $order) {
        if ($k -ge $seg.Count) { continue }
        $cand = $base + '\' + (($seg[$k..($seg.Count - 1)]) -join '\')
        if (Test-FileLP $cand) { $ctx.SrcOffset = $k; return $cand }
    }
    return $null
}

function Add-State($status, $idx, $src, $rel, $size, $hash, $msg) {
    $fields = @((Get-Date).ToUniversalTime().ToString('o'), $status, $idx, $src, $rel, $size, $hash, $msg) |
        ForEach-Object { '"' + (([string]$_) -replace '"', '""') + '"' }
    Add-Content -LiteralPath $ctx.StateFile -Value ($fields -join ',') -Encoding UTF8
}

# Copies one file (blocking), verifies size + SHA256, then renames .part -> final name.
function Copy-OneFile {
    param([string]$Src, [string]$Dst, [long]$ExpectedSize, [string]$ExpectedHash, [string]$Label)

    $srcLP  = ConvertTo-LongPath $Src
    $dstLP  = ConvertTo-LongPath $Dst
    $partLP = $dstLP + '.part'
    $dir    = $Dst.Substring(0, $Dst.LastIndexOf('\'))
    [void][System.IO.Directory]::CreateDirectory((ConvertTo-LongPath $dir))

    $inS = $null; $outS = $null; $sha = $null; $ok = $false
    try {
        $inS  = [System.IO.FileStream]::new($srcLP, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::ReadWrite, $BufferSizeBytes, [System.IO.FileOptions]::SequentialScan)
        $outS = [System.IO.FileStream]::new($partLP, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::None, $BufferSizeBytes, [System.IO.FileOptions]::SequentialScan)
        if ($VerifyHash -and $ExpectedHash) { $sha = [System.Security.Cryptography.SHA256]::Create() }

        $buf   = [byte[]]::new($BufferSizeBytes)
        $total = [long]0
        $sw    = [System.Diagnostics.Stopwatch]::StartNew()
        $lastP = [long]-1000

        while (($n = $inS.Read($buf, 0, $buf.Length)) -gt 0) {
            $outS.Write($buf, 0, $n)
            if ($sha) { [void]$sha.TransformBlock($buf, 0, $n, $null, 0) }
            $total += $n
            if (($sw.ElapsedMilliseconds - $lastP) -ge 500) {
                $lastP = $sw.ElapsedMilliseconds
                $pct = 0
                if ($ExpectedSize -gt 0) { $pct = [int][Math]::Min(100, [Math]::Floor($total * 100 / [double]$ExpectedSize)) }
                $speed = 0; if ($sw.Elapsed.TotalSeconds -gt 0) { $speed = $total / $sw.Elapsed.TotalSeconds }
                Write-Progress -Id 2 -ParentId 1 -Activity "Copying $Label" `
                    -Status ('{0} of {1}  ({2}/s)' -f (Format-Size $total), (Format-Size $ExpectedSize), (Format-Size $speed)) `
                    -PercentComplete $pct
            }
        }

        $actual = ''
        if ($sha) {
            [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
            $actual = [BitConverter]::ToString($sha.Hash).Replace('-', '')
        }
        $outS.Flush()
        $outS.Dispose(); $outS = $null
        $inS.Dispose();  $inS  = $null

        if ($ExpectedSize -gt 0 -and $total -ne $ExpectedSize) {
            throw "SIZE_MISMATCH: expected $ExpectedSize bytes, copied $total"
        }
        if ($sha -and ($actual -ne $ExpectedHash.Trim().ToUpperInvariant())) {
            throw "HASH_MISMATCH: expected $ExpectedHash, got $actual"
        }

        try { [System.IO.File]::SetLastWriteTimeUtc($partLP, [System.IO.File]::GetLastWriteTimeUtc($srcLP)) } catch { }
        if ([System.IO.File]::Exists($dstLP)) { [System.IO.File]::Delete($dstLP) }
        [System.IO.File]::Move($partLP, $dstLP)
        $ok = $true
        return [pscustomobject]@{ Bytes = $total; Hash = $actual; Seconds = $sw.Elapsed.TotalSeconds }
    }
    finally {
        if ($outS) { $outS.Dispose() }
        if ($inS)  { $inS.Dispose() }
        if ($sha)  { $sha.Dispose() }
        if (-not $ok) {
            try { if ([System.IO.File]::Exists($partLP)) { [System.IO.File]::Delete($partLP) } } catch { }
        }
    }
}

# ------------------------------ prompts -------------------------------
Write-Host ''
Write-Host '=== NAS -> local resumable downloader ===' -ForegroundColor Cyan
Write-Host ''

$nasIn   = Read-ExistingPath 'NAS folder path to scan (e.g. \\192.168.3.50\cyber-dfir  or  Z:\)' 'Container'
$nasRoot = (Resolve-Path -LiteralPath $nasIn).ProviderPath

$outIn = ''
while (-not $outIn) { $outIn = Clean-Input (Read-Host 'Output folder path (files will be downloaded here)') }
if (-not (Test-Path -LiteralPath $outIn -PathType Container)) {
    [void](New-Item -ItemType Directory -Path $outIn -Force)
}
$outRoot = ((Resolve-Path -LiteralPath $outIn).ProviderPath).TrimEnd('\')

$csvIn   = Read-ExistingPath 'CSV file with the paths / file names' 'Leaf'
$csvPath = (Resolve-Path -LiteralPath $csvIn).ProviderPath

$ctx.LogFile   = Join-Path $outRoot '_download_log.txt'
$ctx.StateFile = Join-Path $outRoot '_download_state.csv'
if (-not (Test-Path -LiteralPath $ctx.StateFile)) {
    Set-Content -LiteralPath $ctx.StateFile -Encoding UTF8 `
        -Value 'Timestamp,Status,Index,SourcePath,RelativeDest,SizeBytes,SHA256,Message'
}

Write-Log '' 'INFO'
Write-Log ('===== Run started {0} =====' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) 'HEAD'
Write-Log "NAS folder : $nasRoot"
Write-Log "Output     : $outRoot"
Write-Log "CSV        : $csvPath"

# ------------------------------ load CSV ------------------------------
$rows = @(Import-Csv -LiteralPath $csvPath -Encoding UTF8)
if ($rows.Count -eq 0) { Write-Log 'CSV has no rows. Nothing to do.' 'ERROR'; return }
if (-not $rows[0].PSObject.Properties['FullPath']) {
    Write-Log "CSV has no 'FullPath' column. Columns found: $(($rows[0].PSObject.Properties.Name) -join ', ')" 'ERROR'
    return
}
$hasSize = [bool]$rows[0].PSObject.Properties['ExpectedSizeBytes']
$hasHash = [bool]$rows[0].PSObject.Properties['ExpectedSHA256']
Write-Log ("CSV rows   : {0}  (size check: {1}, SHA256 check: {2})" -f $rows.Count, $hasSize, ($hasHash -and $VerifyHash))

# ----------------------- resume: what is already done ------------------
$done = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
try {
    foreach ($r in @(Import-Csv -LiteralPath $ctx.StateFile -Encoding UTF8)) {
        if ($r.Status -eq 'OK') { [void]$done.Add([string]$r.SourcePath) }
    }
} catch { Write-Log "Could not fully read state file: $($_.Exception.Message)" 'WARN' }

$queue = New-Object System.Collections.Generic.List[object]
$alreadyDone = 0; $requeued = 0; $i = 0
foreach ($row in $rows) {
    $i++
    $size = [long]0
    if ($hasSize) { [void][long]::TryParse([string]$row.ExpectedSizeBytes, [ref]$size) }
    $rel  = Get-DestRelative $row
    $dst  = $outRoot + '\' + $rel
    if ($done.Contains([string]$row.FullPath)) {
        $dlp = ConvertTo-LongPath $dst
        $present = $false
        try {
            $present = [System.IO.File]::Exists($dlp)
            if ($present -and $size -gt 0) { $present = ([System.IO.FileInfo]::new($dlp).Length -eq $size) }
        } catch { $present = $false }
        if ($present) { $alreadyDone++; continue }
        $requeued++   # logged as OK before, but missing/changed on disk -> download again
    }
    $hash = ''
    if ($hasHash) { $hash = [string]$row.ExpectedSHA256 }
    $queue.Add([pscustomobject]@{ Index = $i; Src = [string]$row.FullPath; Rel = $rel; Dst = $dst; Size = $size; Hash = $hash })
}

$total = $rows.Count
$remainingBytes = [long]0
foreach ($q in $queue) { $remainingBytes += $q.Size }
$ctx.TotalBytes = $remainingBytes

Write-Log ("Already downloaded & verified on disk : {0}" -f $alreadyDone) 'OK'
if ($requeued -gt 0) { Write-Log ("Logged OK but missing/changed on disk -> will re-download: {0}" -f $requeued) 'WARN' }
Write-Log ("To download now                        : {0} files, {1}" -f $queue.Count, (Format-Size $remainingBytes))

if ($queue.Count -eq 0) { Write-Log 'Everything in the CSV is already downloaded. Nothing to do.' 'OK'; return }
Write-Log ("Resuming at CSV row #{0}" -f $queue[0].Index)

# ----------------------------- pre-flight ------------------------------
# free space (local drive letters only)
try {
    $pr = [System.IO.Path]::GetPathRoot($outRoot)
    if ($pr -and -not $pr.StartsWith('\\')) {
        $free = [System.IO.DriveInfo]::new($pr).AvailableFreeSpace
        Write-Log ("Free space on {0} : {1}" -f $pr, (Format-Size $free))
        if ($free -lt ($remainingBytes + 1GB)) {
            Write-Log 'Free space looks too low for the remaining files.' 'WARN'
            if (-not (Confirm-Yes 'Continue anyway?')) { return }
        }
    }
} catch { }

# long destination paths (Explorer / many tools struggle above 259 chars)
$longCount = @($queue | Where-Object { $_.Dst.Length -ge 259 }).Count
if ($longCount -gt 0) {
    Write-Log "$longCount destination paths are 259+ chars. The copy works (long-path mode), but Explorer may not open them; use a short output folder like D:\X." 'WARN'
}

# can we actually find files under the NAS path? sample up to 8 spread across the queue
$n = $queue.Count
if ($n -le 8) { $pick = @(0..($n - 1)) } else { $pick = @(0..7 | ForEach-Object { [int][Math]::Floor($_ * ($n - 1) / 7) }) }
$found = 0
foreach ($p in $pick) { if (Resolve-Source $queue[$p].Src $nasRoot) { $found++ } }
Write-Log ("Pre-flight: located {0} of {1} sampled files under the NAS path" -f $found, $pick.Count) $(if ($found -eq $pick.Count) { 'OK' } else { 'WARN' })
if ($found -lt $pick.Count) {
    Write-Log 'Some sampled files were not found. Check the NAS path (it should be the share root that contains the folders listed in the CSV).' 'WARN'
    if (-not (Confirm-Yes 'Continue anyway?')) { return }
}

[void](Read-Host 'Press Enter to start (Ctrl+C stops safely at any time)')

# ------------------------------ main loop ------------------------------
$stats   = @{ OK = 0; Missing = 0; Failed = 0; Bytes = [long]0 }
$start   = Get-Date
$pos     = 0
$aborted = $false
$finishedAll = $false

try {
    foreach ($it in $queue) {
        $pos++
        $name = Split-Path -Leaf $it.Rel
        $overallPct = 0
        if ($ctx.TotalBytes -gt 0) { $overallPct = [int][Math]::Min(100, [Math]::Floor($ctx.BytesDone * 100 / [double]$ctx.TotalBytes)) }
        Write-Progress -Id 1 -Activity 'NAS download' -PercentComplete $overallPct `
            -Status ('{0} of {1} this run | CSV row {2}/{3} | {4} of {5}' -f $pos, $queue.Count, $it.Index, $total, (Format-Size $ctx.BytesDone), (Format-Size $ctx.TotalBytes))

        $src = Resolve-Source $it.Src $nasRoot
        if (-not $src) {
            $stats.Missing++
            Add-State 'MISSING' $it.Index $it.Src $it.Rel $it.Size $it.Hash 'Source not found under NAS path'
            Write-Log ("[{0,4}/{1}] MISSING  {2}" -f $it.Index, $total, $it.Rel) 'WARN'
            if (-not (Test-Path -LiteralPath $nasRoot)) {
                Write-Log 'NAS path is no longer reachable. Stopping - reconnect and run again; progress is saved.' 'ERROR'
                $aborted = $true; break
            }
            continue
        }

        $result = $null; $lastErr = ''; $attempt = 0
        while ($attempt -lt $MaxRetries -and -not $result) {
            $attempt++
            try {
                $result = Copy-OneFile -Src $src -Dst $it.Dst -ExpectedSize $it.Size -ExpectedHash $it.Hash -Label $name
            } catch {
                $lastErr = $_.Exception.Message
                Write-Log ("   attempt {0}/{1} failed for {2}: {3}" -f $attempt, $MaxRetries, $name, $lastErr) 'WARN'
                if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySeconds }
            }
        }
        Write-Progress -Id 2 -ParentId 1 -Activity 'Copying' -Completed

        if ($result) {
            $stats.OK++
            $stats.Bytes += $result.Bytes
            $ctx.BytesDone += $it.Size
            Add-State 'OK' $it.Index $it.Src $it.Rel $result.Bytes $result.Hash 'Copied and verified'
            $speed = 0; if ($result.Seconds -gt 0) { $speed = $result.Bytes / $result.Seconds }
            Write-Log ("[{0,4}/{1}] OK  {2,10}  {3,10}/s  {4}" -f $it.Index, $total, (Format-Size $result.Bytes), (Format-Size $speed), $it.Rel) 'OK'
        }
        else {
            $stats.Failed++
            $status = 'FAILED'
            if ($lastErr -like 'HASH_MISMATCH*') { $status = 'HASH_MISMATCH' }
            Add-State $status $it.Index $it.Src $it.Rel $it.Size $it.Hash $lastErr
            Write-Log ("[{0,4}/{1}] {2}  {3}  ({4})" -f $it.Index, $total, $status, $it.Rel, $lastErr) 'ERROR'
            if (-not (Test-Path -LiteralPath $nasRoot)) {
                Write-Log 'NAS path is no longer reachable. Stopping - reconnect and run again; progress is saved.' 'ERROR'
                $aborted = $true; break
            }
        }
    }
    if (-not $aborted) { $finishedAll = $true }
}
finally {
    Write-Progress -Id 2 -ParentId 1 -Activity 'Copying' -Completed
    Write-Progress -Id 1 -Activity 'NAS download' -Completed

    $elapsed = (Get-Date) - $start
    $avg = 0; if ($elapsed.TotalSeconds -gt 0) { $avg = $stats.Bytes / $elapsed.TotalSeconds }
    $overallDone = $alreadyDone + $stats.OK
    Write-Log ''
    Write-Log '----------------------------- SUMMARY -----------------------------' 'HEAD'
    $elapsedTxt = '{0}h {1:00}m {2:00}s' -f [int][Math]::Floor($elapsed.TotalHours), $elapsed.Minutes, $elapsed.Seconds
    Write-Log ("This run : {0} OK ({1}), {2} failed, {3} missing, {4} elapsed, avg {5}/s" -f $stats.OK, (Format-Size $stats.Bytes), $stats.Failed, $stats.Missing, $elapsedTxt, (Format-Size $avg))
    Write-Log ("Overall  : {0} of {1} files downloaded and verified ({2} still to do)" -f $overallDone, $total, ($total - $overallDone)) 'OK'
    if ($finishedAll -and ($total - $overallDone) -eq 0) {
        Write-Log 'All files downloaded.' 'OK'
    } else {
        Write-Log 'Not finished. Run the same command again with the SAME output folder to continue / retry failed files.' 'WARN'
    }
    Write-Log "State file: $($ctx.StateFile)"
    Write-Log "Log file  : $($ctx.LogFile)"
}
}
