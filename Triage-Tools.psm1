<#
.SYNOPSIS
    Модуль для быстрого Threat Hunting и сбора артефактов на Windows-хосте.
.DESCRIPTION
    Содержит функции для анализа процессов, сетевых соединений, автозагрузок,
    проверки Sysmon, поиска LOLBins-активности и генерации структурированных отчётов.
.NOTES
    Автор: B1tBit (Maxim Sedelnikov)
    Версия: 2.0
    Требования: PowerShell 5.1+
#>

# Отключаем строгую типизацию для совместимости
Set-StrictMode -Version 2

# Переменные для экспорта отчёта
$script:OutputLines = [System.Collections.Generic.List[string]]::new()
$script:ColorEnabled = $true

function Write-TriageOutput {
    param(
        [string]$Message,
        [ConsoleColor]$ForegroundColor = [ConsoleColor]::White,
        [ConsoleColor]$BackgroundColor = [ConsoleColor]::Black,
        [switch]$NoNewLine
    )
    if ($script:ColorEnabled -and $Host.UI.RawUI) {
        Write-Host $Message -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor -NoNewline:$NoNewLine
    } else {
        Write-Host $Message -NoNewline:$NoNewLine
    }
    $script:OutputLines.Add($Message)
}

function Get-AdminStatus {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemInfo {
    Write-TriageOutput "[*] Сбор информации о системе..." -ForegroundColor Cyan
    $OS = Get-CimInstance Win32_OperatingSystem
    $info = [PSCustomObject]@{
        Hostname = $env:COMPUTERNAME
        OS = $OS.Caption
        Build = $OS.BuildNumber
        LastBoot = $OS.LastBootUpTime
        CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin = Get-AdminStatus
    }
    Write-TriageOutput "    Хост: $($info.Hostname)"
    Write-TriageOutput "    ОС: $($info.OS) (Build $($info.Build))"
    Write-TriageOutput "    Последняя загрузка: $($info.LastBoot)"
    Write-TriageOutput "    Пользователь: $($info.CurrentUser)"
    Write-TriageOutput ""
    return $info
}

function Get-SuspiciousProcesses {
    param(
        [switch]$IncludeLOLBins
    )
    Write-TriageOutput "[*] Анализ процессов (подозрительные паттерны, LOLBins)..." -ForegroundColor Cyan

    $allProcs = Get-Process -IncludeUserName | Select-Object Id, ProcessName, @{N='UserName';E={$_.UserName}}, Path, StartTime
    $total = $allProcs.Count
    $suspicious = @()

    # Известные LOLBins
    $lolbins = @(
        "powershell.exe", "cmd.exe", "wmic.exe", "mshta.exe", "rundll32.exe",
        "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "cscript.exe", "wscript.exe",
        "msbuild.exe", "installutil.exe", "ieexec.exe", "reg.exe", "sc.exe",
        "schtasks.exe", "net.exe", "net1.exe", "bcdedit.exe", "vssadmin.exe"
    )

    foreach ($proc in $allProcs) {
        $reasons = @()
        $path = $proc.Path
        $name = $proc.ProcessName

        # Проверка на подозрительный путь
        if ($path -match '\\Temp\\|\\Downloads\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\Users\\Public\\') {
            $reasons += "Запущен из временной/пользовательской папки: $path"
        }

        # Двойное расширение
        if ($name -match '\.(exe|scr|bat|ps1|vbs|js)\.exe$') {
            $reasons += "Двойное расширение: $name"
        }

        # Проверка цифровой подписи
        if ($path -and (Test-Path $path)) {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            if ($sig.Status -ne "Valid" -and $sig.Status -ne "NotSigned") {
                $reasons += "Подпись недействительна: $($sig.Status)"
            }
        }

        # LOLBins проверка (если запрошено)
        if ($IncludeLOLBins) {
            $baseName = $name.ToLower()
            if ($baseName -in $lolbins) {
                # Дополнительные эвристики для LOLBins
                $cmdLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" | Select-Object -ExpandProperty CommandLine) -replace "`0", ""
                if ($cmdLine) {
                    $suspiciousPatterns = @(
                        @{Pattern='-enc\s+\S+'; Desc='Base64 encoded command (PowerShell)'},
                        @{Pattern='-EncodedCommand'; Desc='EncodedCommand (PowerShell)'},
                        @{Pattern='IEX\s*\(|Invoke-Expression'; Desc='Invoke-Expression (PowerShell)'},
                        @{Pattern='DownloadString|DownloadFile|Net\.WebClient'; Desc='Download cradle (PowerShell/.NET)'},
                        @{Pattern='process\s+call\s+create'; Desc='WMI process creation (wmic)'},
                        @{Pattern='javascript:'; Desc='JavaScript execution (mshta)'},
                        @{Pattern='regsvr32\s+/s\s+/u\s+/i:'; Desc='Regsvr32 AppLocker bypass'},
                        @{Pattern='certutil\s+-decode'; Desc='Certutil decode (download)'},
                        @{Pattern='bitsadmin\s+/transfer'; Desc='BITSAdmin download'}
                    )
                    foreach ($pat in $suspiciousPatterns) {
                        if ($cmdLine -match $pat.Pattern) {
                            $reasons += "LOLBin [$name] с подозрительными аргументами: $($pat.Desc)"
                            break
                        }
                    }
                }
            }
        }

        if ($reasons.Count -gt 0) {
            $suspicious += [PSCustomObject]@{
                PID = $proc.Id
                Name = $name
                User = $proc.UserName
                Path = $path
                Reasons = ($reasons -join "; ")
            }
        }
    }

    if ($suspicious.Count -gt 0) {
        Write-TriageOutput "    [ВНИМАНИЕ] Обнаружено подозрительных процессов: $($suspicious.Count) / $total" -ForegroundColor Red
        $suspicious | Format-Table -AutoSize | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ -ForegroundColor Yellow }
    } else {
        Write-TriageOutput "    [OK] Явно подозрительных процессов не найдено (из $total)." -ForegroundColor Green
    }
    Write-TriageOutput ""
    return $suspicious
}

function Get-NetworkAnalysis {
    Write-TriageOutput "[*] Анализ сетевых соединений..." -ForegroundColor Cyan
    $conns = Get-NetTCPConnection | Where-Object State -eq Established | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

    $external = @()
    foreach ($c in $conns) {
        if ($c.RemoteAddress -notmatch '^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1|fe80:|0\.0\.0\.0)') {
            $external += $c
        }
    }

    if ($external.Count -gt 0) {
        Write-TriageOutput "    [ВНИМАНИЕ] Установлены соединения с внешними IP:" -ForegroundColor Yellow
        $external | Format-Table -AutoSize | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ -ForegroundColor Yellow }
    } else {
        Write-TriageOutput "    [OK] Нет активных соединений с внешними IP." -ForegroundColor Green
    }
    Write-TriageOutput ""
    return $external
}

function Get-PersistenceAnalysis {
    Write-TriageOutput "[*] Анализ механизмов автозагрузки..." -ForegroundColor Cyan
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $autoRun = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $values.PSObject.Properties | Where-Object Name -notmatch '^PS' | ForEach-Object {
                $autoRun += [PSCustomObject]@{
                    Type = "Registry"
                    Location = $key
                    Name = $_.Name
                    Command = $_.Value
                }
            }
        }
    }

    $startupFolders = @(
        [Environment]::GetFolderPath("CommonStartup"),
        [Environment]::GetFolderPath("Startup")
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            Get-ChildItem $folder -File | ForEach-Object {
                $autoRun += [PSCustomObject]@{
                    Type = "Startup Folder"
                    Location = $folder
                    Name = $_.Name
                    Command = $_.FullName
                }
            }
        }
    }

    $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notmatch '\\Microsoft\\' }
    $suspiciousTasks = @()
    foreach ($task in $tasks) {
        $actions = $task.Actions.Execute
        if ($actions) {
            foreach ($action in $actions) {
                if ($action -match '\.(exe|bat|ps1|vbs|js)') {
                    $suspiciousTasks += [PSCustomObject]@{
                        TaskName = $task.TaskName
                        TaskPath = $task.TaskPath
                        Command = $action
                    }
                }
            }
        }
    }

    Write-TriageOutput "    Элементов в Run/RunOnce: $($autoRun.Count)" -ForegroundColor White
    $autoRun | Format-Table -AutoSize | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ }
    Write-TriageOutput "    Подозрительные запланированные задачи (не Microsoft): $($suspiciousTasks.Count)" -ForegroundColor White
    if ($suspiciousTasks.Count -gt 0) {
        $suspiciousTasks | Format-Table -AutoSize | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ -ForegroundColor Yellow }
    }
    Write-TriageOutput ""
    return @{ AutoRun = $autoRun; SuspiciousTasks = $suspiciousTasks }
}

function Get-SysmonEvents {
    Write-TriageOutput "[*] Проверка Sysmon..." -ForegroundColor Cyan
    $service = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-TriageOutput "    Sysmon не обнаружен. Рекомендуется установить для расширенного мониторинга." -ForegroundColor Yellow
        Write-TriageOutput ""
        return $null
    }

    Write-TriageOutput "    Sysmon установлен: $($service.DisplayName)" -ForegroundColor Green
    $events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($events) {
        Write-TriageOutput "    [Sysmon] Последние 50 событий создания процессов:" -ForegroundColor Cyan
        $events | Select-Object TimeCreated,
            @{N='Image';E={$_.Properties[4].Value}},
            @{N='CommandLine';E={$_.Properties[10].Value}},
            @{N='User';E={$_.Properties[12].Value}},
            @{N='ParentImage';E={$_.Properties[20].Value}} |
            Format-Table -AutoSize -Wrap | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ }
    } else {
        Write-TriageOutput "    События Sysmon не найдены за последние 24 часа." -ForegroundColor Yellow
    }
    Write-TriageOutput ""
    return $events
}

function Get-AdditionalArtifacts {
    Write-TriageOutput "[*] Дополнительные артефакты (Prefetch, Temp, DNS)..." -ForegroundColor Cyan
    $isAdmin = Get-AdminStatus
    $artifacts = @{}

    if ($isAdmin) {
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            $recent = Get-ChildItem $prefetchPath -File | Sort-Object LastWriteTime -Descending | Select-Object -First 20
            Write-TriageOutput "    [Prefetch] Последние 20 файлов Prefetch:" -ForegroundColor Cyan
            $recent | Format-Table Name, LastWriteTime -AutoSize | Out-String | ForEach-Object { Write-TriageOutput $_ }
            $artifacts.Prefetch = $recent
        }
    }

    $tempPath = [Environment]::GetEnvironmentVariable("TEMP")
    $tempFiles = Get-ChildItem $tempPath -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 20
    Write-TriageOutput "    [Temp] Последние 20 файлов в TEMP:" -ForegroundColor Cyan
    $tempFiles | Format-Table Name, LastWriteTime, Length -AutoSize | Out-String | ForEach-Object { Write-TriageOutput $_ }
    $artifacts.TempFiles = $tempFiles

    $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Data, TimeToLive | Sort-Object TimeToLive
    if ($dns) {
        Write-TriageOutput "    [DNS Cache] Кэш DNS записей (первые 30):" -ForegroundColor Cyan
        $dns | Select-Object -First 30 | Format-Table -AutoSize | Out-String -Width 4096 | ForEach-Object { Write-TriageOutput $_ }
        $artifacts.DNSCache = $dns
    }
    Write-TriageOutput ""
    return $artifacts
}

function Get-TriageReport {
    param(
        [switch]$ExportJson,
        [string]$JsonPath,
        [switch]$IncludeLOLBins = $true
    )

    $report = [PSCustomObject]@{
        Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        SystemInfo = Get-SystemInfo
        SuspiciousProcesses = Get-SuspiciousProcesses -IncludeLOLBins:$IncludeLOLBins
        ExternalConnections = Get-NetworkAnalysis
        Persistence = Get-PersistenceAnalysis
        SysmonEvents = Get-SysmonEvents
        AdditionalArtifacts = Get-AdditionalArtifacts
        RiskAssessment = @{}
    }

    # Вычисление риска с защитой от $null
    $riskScore = 0
    $riskReasons = @()
    if ($report.SuspiciousProcesses -and @($report.SuspiciousProcesses).Count -gt 0) { 
        $riskScore += 30
        $riskReasons += "Обнаружены подозрительные процессы."
    }
    if ($report.ExternalConnections -and @($report.ExternalConnections).Count -gt 0) { 
        $riskScore += 20
        $riskReasons += "Обнаружены внешние соединения."
    }
    if ($report.Persistence.SuspiciousTasks -and @($report.Persistence.SuspiciousTasks).Count -gt 0) { 
        $riskScore += 20
        $riskReasons += "Обнаружены нестандартные задачи планировщика."
    }
    if ($report.Persistence.AutoRun -and @($report.Persistence.AutoRun).Count -gt 20) { 
        $riskScore += 10
        $riskReasons += "Большое количество элементов автозагрузки."
    }

    $level = switch ($riskScore) {
        { $_ -ge 50 } { "HIGH" }
        { $_ -ge 20 } { "MEDIUM" }
        default { "LOW" }
    }

    $report.RiskAssessment = @{
        Score = $riskScore
        Level = $level
        Reasons = $riskReasons
    }

    Write-TriageOutput "=== ИТОГОВОЕ РЕЗЮМЕ ===" -ForegroundColor Magenta
    switch ($level) {
        "HIGH" { Write-TriageOutput "    [!] ВЫСОКИЙ УРОВЕНЬ ПОДОЗРЕНИЯ! Рекомендуется немедленное расследование." -ForegroundColor Red }
        "MEDIUM" { Write-TriageOutput "    [*] СРЕДНИЙ УРОВЕНЬ ПОДОЗРЕНИЯ. Требуется дополнительный анализ." -ForegroundColor Yellow }
        "LOW" { Write-TriageOutput "    [OK] НИЗКИЙ УРОВЕНЬ ПОДОЗРЕНИЯ. Явных индикаторов компрометации не обнаружено." -ForegroundColor Green }
    }
    foreach ($reason in $riskReasons) {
        Write-TriageOutput "        - $reason" -ForegroundColor Yellow
    }
    Write-TriageOutput ""

    if ($ExportJson) {
        $report | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding utf8
        Write-TriageOutput "[*] JSON-отчёт сохранён: $JsonPath" -ForegroundColor Green
    }

    return $report
}

function Export-TriageTextReport {
    param(
        [string]$Path = ".\Triage_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    )
    $script:OutputLines -join "`r`n" | Out-File -FilePath $Path -Encoding utf8
    Write-TriageOutput "[*] Текстовый отчёт сохранён: $Path" -ForegroundColor Green
}

Export-ModuleMember -Function Get-TriageReport, Export-TriageTextReport, Write-TriageOutput, Get-AdminStatus