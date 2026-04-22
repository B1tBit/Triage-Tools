<#
.SYNOPSIS
    Запуск быстрого анализа хоста с формированием текстового и JSON-отчётов.
.DESCRIPTION
    Вызывает функции модуля Triage-Tools и сохраняет результаты в файлы.
.PARAMETER ExportReport
    Сохранить текстовый отчёт.
.PARAMETER ExportJson
    Сохранить JSON-отчёт.
.PARAMETER NoColor
    Отключить цветной вывод.
.EXAMPLE
    .\Invoke-Triage.ps1 -ExportReport -ExportJson
#>

param(
    [switch]$ExportReport,
    [switch]$ExportJson,
    [switch]$NoColor
)

# Разрешаем выполнение скрипта, если политика ограничивает
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Импортируем модуль
Import-Module "$PSScriptRoot\Triage-Tools.psm1" -Force -ErrorAction Stop

$script:ColorEnabled = -not $NoColor

# Пути для отчётов
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$baseName = "Triage_$($env:COMPUTERNAME)_$timestamp"
$reportPath = Join-Path $PSScriptRoot "$baseName.txt"
$jsonPath = Join-Path $PSScriptRoot "$baseName.json"

# Запускаем сбор
$report = Get-TriageReport -ExportJson:$ExportJson -JsonPath $jsonPath -IncludeLOLBins

# Сохраняем текстовый отчёт
if ($ExportReport) {
    Export-TriageTextReport -Path $reportPath
}

# Если ни один флаг не указан, просто выводим в консоль без сохранения
if (-not $ExportReport -and -not $ExportJson) {
    Write-Host "`nОтчёты не сохранены. Используйте -ExportReport и/или -ExportJson для записи в файлы." -ForegroundColor Cyan
}