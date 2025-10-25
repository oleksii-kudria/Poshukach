# 🧩 Завдання 20 — Уточнення правила `vendor` додатковими умовами (`require` / `except`)

## 🎯 Мета
Зменшити хибні спрацювання правил за вендором (напр., TP-Link) шляхом уведення **позитивних ознак** пристрою (`require`) та **винятків** (`except`).  
ПК із **TP-Link Wireless USB Adapter** не повинен трактуватись як мережеве обладнання або потрапляти до ignore лише через `vendor == "TP-Link Systems Inc"`.

---

## 🗂️ Зміни у форматі конфігів
Оновити схему обох файлів правил — **`configs/device_network.yml`** та **`configs/device_ignore.yml`**.

### Було
```yaml
rules:
  - mode: vendor
    patterns:
      - "TP-Link Systems Inc"
```

### Стало
```yaml
rules:
  - mode: vendor
    patterns:
      - "TP-Link Systems Inc"

    require:
      name_contains: ["Archer", "Deco", "TL-", "AP", "Router", "Access Point"]
      vendor_class_contains: ["router", "ap", "openwrt", "tp-link"]
      vendor_class_regex: ["^(tp|router|ap|openwrt)"]
      oui_prefixes: []

    except:
      name_regex: ["^(DESKTOP|LAPTOP|PC|WIN-|DESKTOP-)", "(?i)MacBook|iPhone|Android"]
      name_contains: ["DESKTOP", "LAPTOP"]
      oui_prefixes: ["3C:64:CF", "20:23:51"]
```

> `patterns`, `name_contains`, `vendor_class_contains` — **case-insensitive contains**.  
> `*_regex` — компіляція з `re.IGNORECASE`.  
> `oui_prefixes` — порівнювати у форматі `XX:XX:XX` (верхній регістр).

---

## 🔎 Логіка матчингу
1. Якщо `vendor` збігається з `patterns`.
2. Якщо `except` спрацьовує — правило ігнорується.
3. Якщо є `require` — має спрацювати хоча б одне. Якщо його немає — залишаємо стару поведінку.
4. Результат:
   - `device_network.yml` → рядок у `data/result/dhcp-network.csv`.
   - `device_ignore.yml` → рядок у `data/result/dhcp-ignore.csv`.

---

## 🧭 Потоки
- **A:** `random → ignore (нові правила) → MAC → duplicates`  
- **B:** `network (нові правила)`  

---

## 🛡️ Бек-компатибільність
- `require`/`except` опційні.
- Якщо відсутні — логіка не змінюється.

---

## 🧪 Приклад
| MAC | Vendor | Name | Результат |
|------|---------|--------|-----------|
| 20:23:51:03:3D:EE | TP-Link Systems Inc | ArcherC54 | ✅ мережеве обладнання |
| 3C:64:CF:55:26:0C | TP-Link Systems Inc | DESKTOP-123ASD | 🚫 не мережеве / не ignore |

---

## 🖨️ Логи
```
🔧 vendor-rule: applied with require/except (device_network.yml)
   • matched vendor: TP-Link Systems Inc
   • require hit: name_contains → "Archer"
   • except hit: none
```

---

## 📦 Код
- Оновити парсер YAML для обох файлів.
- Додати функції:
  - `match_vendor_patterns(vendor, patterns)`
  - `require_hit(row, require_cfg)`
  - `except_hit(row, except_cfg)`
- Підтримати поля: `name`, `vendor`, `mac`, `vendorClass`.

---

## ✅ Критерії
- [ ] TP-Link адаптери не потрапляють у ignore/network.
- [ ] TP-Link роутери (Archer, Deco, TL-) потрапляють.
- [ ] `require`/`except` необов’язкові.
- [ ] Логи показують `require`/`except`.
- [ ] Є юніт-тести на TP-Link.

---

## ✍️ Подальші кроки
- Додати `configs/adapters.yml` з OUI для клієнтських адаптерів.
- У майбутньому — підтримати `vendorClass` (DHCP Option 60).
