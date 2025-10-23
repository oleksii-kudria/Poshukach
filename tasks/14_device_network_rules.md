# 🧩 Завдання 14 — Підтримка `configs/device_network.yml` і вивід у `dhcp-network.csv`

## 🎯 Мета
Додати **другий шар правил** (на додачу до `configs/device_ignore.yml`) — новий файл `configs/device_network.yml`.  
Якщо рядок з `data/interim/dhcp.csv` відповідає будь-якому з цих правил, він має бути записаний до **`data/result/dhcp-network.csv`**.

> Перша перевірка за `configs/device_ignore.yml` **залишається без змін**: збіг —> `data/result/dhcp-ignore.csv`, і такий рядок **не потрапляє** у `dhcp-true.csv` / `dhcp-false.csv`.

---

## 🗂️ Новий файл конфігурації
Шлях: `configs/device_network.yml`

**Структура — аналогічна** `device_ignore.yml`, підтримуються режими:
- `prefix` — імʼя `name` починається з патерну;
- `contains` — імʼя `name` містить патерн;
- `regex` — частковий або повний збіг за регулярним виразом;
- `vendor` — збіг за полем `vendor` (див. Завдання 11); порівняння — contains, case-insensitive.

Приклад:
```yaml
rules:
  - mode: prefix
    patterns:
      - "Switch-"
      - "AP-"

  - mode: contains
    patterns:
      - "Router"
      - "Firewall"

  - mode: regex
    patterns:
      - "^core-(sw|rt)-\d+$"

  - mode: vendor
    patterns:
      - "Cisco"
      - "Juniper"
      - "Ubiquiti"
      - "MikroTik"
      - "TP-Link"
```

> Порівняння для `prefix/contains/vendor` — **без урахування регістру**.  
> Для `regex` — компіляція з `re.IGNORECASE`, використовується `search`.

---

## 🔁 Порядок застосування правил при формуванні `data/result/*.csv`

Для кожного рядка `data/interim/dhcp.csv`:

1. Якщо `randomized == true` → логіка Завдання 13 (запис у `data/result/dhcp-random.csv`) і **більше не обробляти** цей рядок.
2. **Перевірка за `configs/device_ignore.yml`** (режими `prefix/contains/regex/vendor` по `name`/`vendor`):  
   - якщо збіг —> **`data/result/dhcp-ignore.csv`**, і **не** перевіряти MAC, **не** писати в інші файли → `continue`.
3. **Перевірка за `configs/device_network.yml`** (аналогічні режими):  
   - якщо збіг —> **`data/result/dhcp-network.csv`**, і **не** перевіряти MAC, **не** писати в інші файли → `continue`.
4. Якщо жодне правило не спрацювало → діяти як у Завданні 07:  
   - якщо `mac` ∈ `data/interim/mac.csv` —> `data/result/dhcp-true.csv`;  
   - інакше —> `data/result/dhcp-false.csv`.

> Таким чином пріоритет: `random` → `ignore` → `network` → перевірка MAC.

---

## 📤 Вивід у консоль (приклад)
```
🟡 ignore: 12
🔷 network: 21
✅ true: 84
⚠️ false: 31
🔹 random: 5
📁 data/result/{dhcp-ignore.csv, dhcp-network.csv, dhcp-true.csv, dhcp-false.csv, dhcp-random.csv}
```

---

## ✅ Критерії прийняття
- [ ] Додано і використовується файл `configs/device_network.yml` з режимами `prefix/contains/regex/vendor`.
- [ ] Рядки, що збігаються з правилами `device_network.yml`, записуються до `data/result/dhcp-network.csv`, без MAC‑перевірки.
- [ ] Пріоритет обробки: `random` → `ignore` → `network` → `mac true/false`.
- [ ] Формати вивідних CSV ідентичні `data/interim/dhcp.csv`.
