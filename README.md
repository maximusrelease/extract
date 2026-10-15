# Extract 🔎

A PowerShell tool to recursively scan NAS shares, calculate SHA-256 hashes, and export file inventories to CSV for forensic comparison.

## Usage

**Step 1:** Open PowerShell and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

**Step 2:** Download and execute the script:

```powershell
$Url="https://raw.githubusercontent.com/maximusrelease/extract/refs/heads/main/recovery.ps1"; $Response=Invoke-WebRequest -Uri $Url -ErrorAction Stop; $ScriptText=$Response.Content; $ScriptBlock=[scriptblock]::Create($ScriptText); & $ScriptBlock
```

**Step 3:** Enter the NAS folder path when prompted, for example:

```text
\\192.168.1.100\Share\before_recovered
```

## Output

The script generates two CSV files on your Desktop:

- **Inventory CSV:** File paths, sizes, timestamps, and SHA-256 hashes.
- **Error CSV:** Files or directories that could not be processed.

**Step 4:** Copy unique files to another nas share

```powershell
$Url="https://raw.githubusercontent.com/maximusrelease/extract/refs/heads/main/copy.ps1"; $Response=Invoke-WebRequest -Uri $Url -ErrorAction Stop; $ScriptText=$Response.Content; $ScriptBlock=[scriptblock]::Create($ScriptText); & $ScriptBlock
```
