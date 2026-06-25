$ErrorActionPreference = 'SilentlyContinue'
$report = "output/ACQ-IR-namtdc01-20250702-0100/report.md"
$miss = 0
while ($true) {
  Start-Sleep -Seconds 30
  $alive = (Get-CimInstance Win32_Process -Filter "ProcessId=10024").CommandLine -match 'main.py investigate'
  if (Test-Path $report) { Write-Output "[wait] report.md present -> host 1 finished cleanly"; break }
  if (-not $alive) { $miss++ } else { $miss = 0 }
  if ($miss -ge 2) { Write-Output "[wait] investigator PID 10024 gone (2x) -> host 1 ended"; break }
}
Write-Output ("[wait] done at " + (Get-Date))
