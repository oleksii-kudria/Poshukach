# 🧩 Завдання 03 — Агрегація DHCP-логів у `data/interim/dhcp.csv`

## 🎯 Мета
Зчитати всі файли `data/raw/dhcp/*.csv` (ігноруючи `*.example.csv`) з форматами заголовків як у прикладі нижче, згрупувати записи за MAC‑адресою та сформувати агрегований файл `data/interim/dhcp.csv` з полями:
```
source,ip,mac,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
```

Після успішного запису вивести в консоль повідомлення з кількістю рядків, записаних до `data/interim/dhcp.csv` (без заголовка).

---

## 📥 Вхідні дані (приклад форматів `data/raw/dhcp/*.csv`)
### Варіант A (мінімальний приклад)
```
source,ip,mac,name,firstDate,lastDate,count,randomized
10.0.0.10,192.168.0.10,AA:BB:CC:DD:EE:FF,Device1,1754562443848,1754562532771,1,true
```

### Варіант B (основний для цього завдання)
```
logSourceIdentifier,sourcMACAddress,payloadAsUTF,deviceTime
"10.0.0.10","EE:3C:E7:DA:8E:B4","dhcp,info defconf assigned 192.168.1.60 for EE:3C:E7:DA:8E:B4","1755006684895"
"10.0.0.10","86:6C:43:84:70:2F","dhcp,info defconf assigned 192.168.1.69 for 86:6C:43:84:70:2F Xiaomi-14T-Pro","1755006240482"
```

> ПРИМІТКА: У полі `payloadAsUTF` IP і (опційно) імʼя пристрою зʼявляються після MAC:  
> • приклад **без імені**: `... assigned 192.168.1.60 for EE:3C:E7:DA:8E:B4`  
> • приклад **з іменем**: `... assigned 192.168.1.69 for 86:6C:43:84:70:2F Xiaomi-14T-Pro`

---

## 🧾 Правила мапінгу та агрегації
- `mac` = `sourcMACAddress`. **MAC у вихідному файлі має бути унікальним** (один рядок на MAC).
- `source` = останнє (за часом) значення `logSourceIdentifier` для цього MAC (беремо запис з максимальним `deviceTime`).
- `ip` = IP‑адреса, витягнута з `payloadAsUTF`, **остання за часом** (з запису з максимальним `deviceTime`).
- `name` = ім’я з `payloadAsUTF` після MAC (якщо відсутнє — записати `unknown`).  
  Приклад відсутності: `... for EE:3C:E7:DA:8E:B4` → `name = unknown`.
- `firstDateEpoch` = **мінімальне** `deviceTime` (epochtime у мілісекундах або секундах — не змінювати одиниці, використовувати як є у вхідних файлах).  
- `lastDateEpoch` = **максимальне** `deviceTime`.
- `firstDate` = `firstDateEpoch` у форматі `YYYY.MM.DD HH:MM` (таймзона `Europe/Kyiv`).  
- `lastDate`  = `lastDateEpoch` у форматі `YYYY.MM.DD HH:MM` (таймзона `Europe/Kyiv`).
- `count` = скільки разів MAC зустрічається загалом у всіх вхідних файлах.
- `randomized` = `true`, якщо MAC **рандомний**, і `false`, якщо **дійсний**.  
  **Критерій**: MAC вважається рандомним, якщо встановлений **локально керований** біт у першому октеті (U/L bit = 1). Тобто, якщо (перший байт & `0x02`) != 0 → `randomized = true`.
- `dateList` = усі часи підключення для цього MAC списком у форматі epochtime, відсортовані за зростанням, через `, ` (кома + пробіл).

> Якщо зустрічаються записи для одного MAC з різними `logSourceIdentifier`, то у підсумок у полі `source` потрапляє **саме значення з останнього за часом** запису (за `deviceTime`).

---

## 🧠 Технічні вимоги
- Мова: **Python 3.10+**. Скрипт запуску: `scripts/psh.py`.
- Директорії `data/raw/dhcp/` та `data/interim/` — відносно кореня репозиторію. За потреби — створити `data/interim/`.
- Ігнорувати всі файли, що закінчуються на `.example.csv`.
- Код повинен:
  - коректно читати UTF‑8/UTF‑8‑SIG,
  - авто‑визначати роздільник через `csv.Sniffer` з fallback на `,`,
  - обробляти порожні файли та відсутні заголовки (помилка → зупинка обробки),
  - бути стійким до пробілів навколо назв колонок (strip).
- Під час зчитування `deviceTime`:
  - підтримати як **мілісекунди**, так і **секунди** (якщо значення виглядає як 13‑значне → це мілісекунди; 10‑значне → секунди; зберігати **оригінальні** значення у `dateList` та `firstDateEpoch/lastDateEpoch`, але для `firstDate/lastDate` конвертувати в datetime).
- Вихідний CSV має містити рівно такі колонки та порядок:
  ```
  source,ip,mac,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
  ```

---

## 🔎 Парсинг `payloadAsUTF`
- Витягнути IP: шаблон `assigned\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+for`.
- Витягнути MAC: шаблон `for\s+(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})`.
- Ім’я (необовʼязкове): **усе після MAC** до кінця рядка (trim). Якщо порожньо — `unknown`.

---

## 📤 Вивід у консоль
Після запису `data/interim/dhcp.csv` вивести:
```
✅ Записано рядків до data/interim/dhcp.csv: <N>
```

---

## 🧪 Приклад очікуваного результату (рядок)
```
source,ip,mac,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
10.0.0.10,192.168.0.10,AA:BB:CC:DD:EE:FF,Device1,2025.08.07 10:27,2025.08.08 15:22,1754562443848,1754666536771,1,false,"1754562443848, 1754655536771, 1754666536771"
```

---

## ✅ Критерії прийняття
- [ ] Коректно зчитуються всі вхідні CSV з `data/raw/dhcp/`, ігноруються `*.example.csv`.
- [ ] Групування виконується за MAC; у вихідному файлі кожен MAC рівно один раз.
- [ ] `source` та `ip` беруться з **останнього за часом** запису (максимальний `deviceTime`).
- [ ] `name` коректно парситься з `payloadAsUTF`; якщо імені немає — `unknown`.
- [ ] `firstDateEpoch`/`lastDateEpoch` відповідають мін/макс `deviceTime`; `firstDate`/`lastDate` — у форматі `YYYY.MM.DD HH:MM` (Europe/Kyiv).
- [ ] `randomized` визначається за U/L‑бітом першого октету MAC.
- [ ] `dateList` містить **усі** значення `deviceTime` для MAC, відсортовано, у вихідному форматі.
- [ ] В кінець роботи виводиться кількість записаних рядків.
