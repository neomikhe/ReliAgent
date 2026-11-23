# Sondea cada ~200 ms las conexiones TCP de los procesos de Ollama y anota
# las que no son de loopback. Termina cuando existe el archivo $Stop.
param([string]$Log, [string]$Stop)
$loopback = @('127.0.0.1', '::1', '0.0.0.0', '::')
$seen = @{}
$samples = 0
while (-not (Test-Path -LiteralPath $Stop)) {
    $pids = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -like 'ollama*' } | ForEach-Object { $_.Id })
    if ($pids.Count -gt 0) {
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $pids -contains $_.OwningProcess -and $loopback -notcontains $_.RemoteAddress } |
            ForEach-Object {
                $key = "$($_.RemoteAddress):$($_.RemotePort) $($_.State)"
                if (-not $seen.ContainsKey($key)) {
                    $seen[$key] = 1
                    Add-Content -LiteralPath $Log -Value ("{0} pid={1} {2}" -f (Get-Date -Format 'HH:mm:ss'), $_.OwningProcess, $key)
                }
            }
    }
    $samples++
    Start-Sleep -Milliseconds 200
}
Add-Content -LiteralPath $Log -Value "samples=$samples"
