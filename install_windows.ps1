<#
.SYNOPSIS
  Installs OpenScore on Windows 10/11.

.DESCRIPTION
  * Python 3.11+ (via winget if missing)
  * Python requirements
  * Optional tools: Nmap (winget), nuclei + subfinder (latest GitHub release -> .\tools\)
  testssl.sh is bash-only; OpenScore's built-in TLS checks are used instead on Windows
  (or run OpenScore inside WSL for testssl.sh support).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
  powershell -ExecutionPolicy Bypass -File .\install_windows.ps1 -NoTools
#>
param([switch]$NoTools)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # makes Invoke-WebRequest much faster
Set-Location $PSScriptRoot

function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("Path", "User")
}
# Windows PowerShell 5.1 + $ErrorActionPreference="Stop" can turn a native tool's stderr output
# into a terminating NativeCommandError. Run native commands with "Continue" and judge them by
# their exit code instead.
function Invoke-Native {
    param([Parameter(Mandatory)][string]$Exe, [string[]]$Arguments = @())
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $global:LASTEXITCODE = 0
        & $Exe @Arguments | Out-Host          # keep tool output out of the return value
        return [int]$LASTEXITCODE
    } catch {
        Write-Warning "$Exe failed to start: $_"
        return 1
    } finally {
        $ErrorActionPreference = $prev
    }
}
function Find-Python {
    foreach ($s in @("py -3", "python", "python3")) {
        $c = @($s -split " ")
        if (Have $c[0]) {
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $pre = @($c | Select-Object -Skip 1)
                $v = & $c[0] @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($LASTEXITCODE -eq 0 -and $v -and [version]"$v".Trim() -ge [version]"3.11") { return , $c }
            } catch { } finally { $ErrorActionPreference = $prev }
        }
    }
    return $null
}

Write-Host "[*] Checking for Python 3.11+" -ForegroundColor Cyan
$py = Find-Python
if (-not $py) {
    if (-not (Have "winget")) { throw "Python 3.11+ not found and winget unavailable. Install Python from https://www.python.org/downloads/ (tick 'Add to PATH') and re-run." }
    Write-Host "[*] Installing Python 3.12 via winget"
    $rc = Invoke-Native "winget" @("install", "-e", "--id", "Python.Python.3.12", "--scope", "user", "--accept-source-agreements", "--accept-package-agreements")
    if ($rc -ne 0) { Write-Warning "winget exited with $rc - checking for Python anyway" }
    Refresh-Path
    $py = Find-Python
    if (-not $py) { throw "Python installed but not on PATH yet - open a new PowerShell window and re-run this script." }
}
Write-Host "    using: $($py -join ' ')"
$PyExe = $py[0]
$PyPre = @($py | Select-Object -Skip 1)       # e.g. "-3" for the py launcher
function Invoke-Py([string[]]$PyArgs) { return Invoke-Native $PyExe ($PyPre + $PyArgs) }

Write-Host "[*] Installing Python requirements" -ForegroundColor Cyan
$rc = Invoke-Py @("-m", "pip", "install", "--upgrade", "--quiet", "pip")
if ($rc -ne 0) { Write-Warning "pip self-upgrade exited with $rc - continuing with the current pip" }
$rc = Invoke-Py @("-m", "pip", "install", "--quiet", "-r", "requirements.txt")
if ($rc -ne 0) { throw "pip install -r requirements.txt failed (exit $rc)" }

if (-not $NoTools) {
    # ---- Nmap
    if (Have "nmap") {
        Write-Host "[=] nmap already installed"
    } elseif (Have "winget") {
        Write-Host "[*] Installing Nmap via winget" -ForegroundColor Cyan
        $rc = Invoke-Native "winget" @("install", "-e", "--id", "Insecure.Nmap", "--accept-source-agreements", "--accept-package-agreements")
        if ($rc -ne 0) { Write-Warning "Nmap install failed (winget exit $rc) - OpenScore will use its built-in port scanner." }
        Refresh-Path
        Write-Host "    NOTE: Nmap on Windows needs Npcap (https://npcap.com). If scans fail, install Npcap" -ForegroundColor Yellow
        Write-Host "    or just skip it - OpenScore falls back to a built-in TCP connect scan." -ForegroundColor Yellow
    }

    # ---- nuclei + subfinder from GitHub releases into .\tools
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "windows_arm64" } else { "windows_amd64" }
    New-Item -ItemType Directory -Force -Path "tools" | Out-Null
    foreach ($tool in @("nuclei", "subfinder")) {
        if ((Have $tool) -or (Test-Path "tools\$tool.exe")) { Write-Host "[=] $tool already present"; continue }
        Write-Host "[*] Downloading latest $tool ($arch)" -ForegroundColor Cyan
        try {
            $hdr = @{ "User-Agent" = "openscore-installer" }
            if ($env:GITHUB_TOKEN) { $hdr["Authorization"] = "Bearer $env:GITHUB_TOKEN" }   # CI: avoids the 60 req/h anonymous limit
            $rel = Invoke-RestMethod "https://api.github.com/repos/projectdiscovery/$tool/releases/latest" -Headers $hdr
            $asset = $rel.assets | Where-Object { $_.name -like "*_$arch.zip" } | Select-Object -First 1
            if (-not $asset) { throw "no $arch build in release $($rel.tag_name)" }
            $zip = Join-Path $env:TEMP $asset.name
            Invoke-WebRequest $asset.browser_download_url -OutFile $zip
            Expand-Archive $zip -DestinationPath "tools\_$tool" -Force
            Get-ChildItem "tools\_$tool" -Recurse -Filter "$tool.exe" | Select-Object -First 1 | Move-Item -Destination "tools\$tool.exe" -Force
            Remove-Item "tools\_$tool", $zip -Recurse -Force
            Write-Host "    installed tools\$tool.exe ($($rel.tag_name))"
        } catch {
            Write-Warning "Could not install ${tool}: $_  (optional - OpenScore works without it)"
        }
    }
    if (Test-Path "tools\nuclei.exe") {
        Write-Host "[*] Downloading nuclei templates" -ForegroundColor Cyan
        $rc = Invoke-Native ".\tools\nuclei.exe" @("-update-templates", "-silent")
        if ($rc -ne 0) { Write-Warning "nuclei template update exited with $rc - run '.\tools\nuclei.exe -update-templates' later (optional)." }
    }
    Write-Host "    (Windows Defender may scan or quarantine security tools in .\tools - add an exclusion if needed.)" -ForegroundColor DarkGray
}

Write-Host "[*] Installing headless Chromium for screenshot evidence" -ForegroundColor Cyan
$rc = Invoke-Py @("-m", "playwright", "install", "chromium")
if ($rc -ne 0) { Write-Warning "Chromium download failed (exit $rc) - scans still work, just without screenshots." }

Write-Host "[*] Running offline self-tests" -ForegroundColor Cyan
$failed = @()
if ((Invoke-Py @("tests\test_dns_email.py")) -ne 0) { $failed += "test_dns_email" }
if ((Invoke-Py @("tests\test_features.py")) -ne 0) { $failed += "test_features" }
if ((Invoke-Py @("-m", "pip", "install", "--quiet", "pytest")) -ne 0) {
    $failed += "pip install pytest"
} elseif ((Invoke-Py @("-m", "pytest", "-q", "tests\test_screenshots.py")) -ne 0) {
    $failed += "test_screenshots"
}
if ($failed) {
    Write-Host "[!] Self-tests FAILED: $($failed -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[+] Done. Try a passive scan:" -ForegroundColor Green
Write-Host "      .\openscore.bat example.com --client ""Example Inc"" --open"
Write-Host ""
Write-Host "    Optional API keys (persist for your user):"
Write-Host "      setx ABUSEIPDB_KEY your-key      # free: https://www.abuseipdb.com/account/api"
Write-Host "      setx GREYNOISE_KEY your-key      # optional"
Write-Host "      setx HIBP_KEY your-key           # paid; domain must be verified in HIBP"
