# 🧩 Завдання 12 — Підтримка `mode: vendor` у `configs/device_ignore.yml` і вивід у `dhcp-ignore.csv`

## 🎯 Мета
Розширити правила ігнорування пристроїв у `configs/device_ignore.yml`, додавши **режим `vendor`**.  
Під час формування результатів (`data/result/dhcp-true.csv`, `data/result/dhcp-false.csv`, `data/result/dhcp-ignore.csv`) — **враховувати** ці правила: якщо `vendor` відповідає одному з патернів режиму `vendor`, **рядок записується у `dhcp-ignore.csv`** (MAC не перевіряється).

---

## 🗂️ Оновлення `configs/device_ignore.yml`

Додайте секцію з правилами типу `vendor` (приклад):
```yaml
rules:
  - mode: vendor
    patterns:
      - "Ubiquiti Inc"
      - "Routerboard.com"
      - "TP-Link Systems Inc"
```
> Порівняння **без урахування регістру** (case‑insensitive), допускається **підрядок** (contains).

> Поле `vendor` повинно існувати у `data/interim/dhcp.csv` (див. Завдання 11).

---

## 🔁 Порядок застосування правил при формуванні `data/result/*.csv`
Для кожного рядка `data/interim/dhcp.csv` (обробляються лише `randomized == false`):
1. **Перевірка за `mode: prefix/contains/regex`** (поле `name`) — з Завдання 08–09. Якщо збіг є → **записати у `dhcp-ignore.csv`**, не перевіряти MAC → `continue`.
2. **Перевірка за `mode: vendor`** (поле `vendor`, додане у Завданні 11). Якщо збіг є → **записати у `dhcp-ignore.csv`**, не перевіряти MAC → `continue`.
3. Якщо жодне правило не спрацювало → діяти як у Завданні 07 (перевірка наявності `mac` у `data/interim/mac.csv`):
   - знайдено → `dhcp-true.csv`;
   - не знайдено → `dhcp-false.csv`.

---

## 🧪 Перевірка працездатності
1. Переконатися, що `data/interim/dhcp.csv` містить колонку `vendor` (Завдання 11).  
2. Додати в `configs/device_ignore.yml` секцію з `mode: vendor` і наведеними патернами.  
3. Запустити збірку результатів (логіка Завдань 07–09).  
4. Переконатися, що рядки з `vendor` ≈ `Ubiquiti Inc`, `Routerboard.com`, `TP-Link Systems Inc` потрапляють до `data/result/dhcp-ignore.csv`.

---

## ✅ Критерії прийняття
- [ ] Підтримується `mode: vendor` у `configs/device_ignore.yml` (case‑insensitive contains).
- [ ] Рядки з відповідним `vendor` записуються у `data/result/dhcp-ignore.csv` без перевірки MAC.
- [ ] Порядок застосування правил: `name`‑based → `vendor`‑based → MAC‑перевірка.
- [ ] Формат результатів не змінено (ідентичний `data/interim/dhcp.csv`).

