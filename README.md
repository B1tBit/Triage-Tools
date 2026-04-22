# 🔍 Triage-Tools

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/B1tBit/Triage-Tools/graphs/commit-activity)

**Triage-Tools** — это модуль PowerShell для быстрого сбора артефактов и Threat Hunting на Windows-хостах.  
Разработан для специалистов **SOC**, **IR-команд** и **пентестеров**, которым нужно за минуту получить полную картину подозрительной активности на конечной точке.

---

## 🚀 Возможности

### 🔎 Сбор артефактов
- **Системная информация:** ОС, версия, время последней загрузки, текущий пользователь.
- **Процессы:** анализ путей, двойных расширений, отсутствия цифровой подписи.
- **LOLBins-детект:** поиск системных утилит (`powershell.exe`, `wmic.exe`, `certutil.exe`, `bitsadmin.exe` и др.) с подозрительными аргументами (Base64, download cradle, обход AppLocker).
- **Сетевые соединения:** выявление установленных подключений к внешним IP-адресам.
- **Автозагрузка:** анализ Run/RunOnce, Startup Folder, запланированных задач (исключая задачи Microsoft).
- **Sysmon:** просмотр событий создания процессов (Event ID 1) за последние 24 часа.
- **Дополнительные артефакты:** Prefetch, содержимое `%TEMP%`, кэш DNS.

### 📊 Оценка риска
Автоматический расчёт уровня подозрительности:
- `LOW` — явных индикаторов компрометации не найдено.
- `MEDIUM` — требуется дополнительный анализ.
- `HIGH` — обнаружены серьёзные аномалии, рекомендуется немедленное расследование.

### 📤 Экспорт результатов
- **Консольный вывод** с цветовой подсветкой.
- **Текстовый отчёт** (`.txt`) — полная копия консольного вывода.
- **JSON-отчёт** (`.json`) — структурированные данные для интеграции с SIEM/SOAR.

---

## 📦 Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/B1tBit/Triage-Tools.git
   cd Triage-Tools
