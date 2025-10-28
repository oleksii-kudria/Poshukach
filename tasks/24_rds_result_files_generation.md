# 🧩 Завдання 24 — Формування результативних файлів для RDS (`data/result/rds-*.csv`)

## 🎯 Мета
Розширити функціонал команди:
```bash
python3 scripts/psh.py rds
```
щоб після створення **`data/interim/rds.csv`** відбувалося автоматичне формування набору результативних файлів у директорії **`data/result/`**, аналогічно до логіки, реалізованої для DHCP.

---

## 📦 Результуючі файли
Після обробки повинні бути створені:

```
data/result/rds-false.csv
data/result/rds-ignore.csv
data/result/rds-network.csv
data/result/rds-random.csv
data/result/rds-true.csv
```

---

## 🧩 Джерело даних
- Вхідний файл: **`data/interim/rds.csv`**
- Довідники:
  - **`data/cache/oui.csv`** — для визначення вендора.
  - **`configs/device_ignore.yml`**
  - **`configs/device_network.yml`**

---

## ⚙️ Логіка обробки

### 1. Початковий поділ
Для кожного запису з `data/interim/rds.csv` перевірити:

- Якщо `randomized == true` → додати рядок у **`data/result/rds-random.csv`**  
  (аналогічно логіці з DHCP).

- Якщо пристрій відповідає правилам із **`configs/device_ignore.yml`** →  
  записати до **`data/result/rds-ignore.csv`**.

- Якщо пристрій відповідає правилам із **`configs/device_network.yml`** →  
  записати до **`data/result/rds-network.csv`**.

> Усі перевірки (`mode: prefix`, `contains`, `regex`, `vendor`) працюють за тією ж логікою, що й у DHCP.

---

### 2. MAC-збіги
- Для всіх записів, які **не потрапили до `ignore` / `network` / `random`**, необхідно перевірити, чи є MAC у **`data/interim/mac.csv`**.
  - Якщо MAC знайдено → додати до **`rds-true.csv`**  
    (пристрій має відповідність у AV).
  - Якщо MAC не знайдено → додати до **`rds-false.csv`**  
    (пристрій не має відповідності у AV).

---

### 3. Порядок обробки (pipeline)
```
random → ignore → network → перевірка MAC → результат (true/false)
```

---

### 4. Формат вихідних файлів
Кожен результативний файл повинен мати **ідентичну структуру шапки**, як і `data/interim/rds.csv`:
```
source,ip,mac,vendor,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
```

---

## 🖨️ Повідомлення у консоль
```
✅ Виявлено RDS-записів у data/interim/rds.csv: 1324
✅ Виявлено MAC-адрес із random: 18
✅ Виявлено пристроїв, що відповідають правилам ignore: 22
✅ Виявлено мережевих пристроїв: 7
✅ Виявлено RDS із AV-збігом: 834
⚠️ Виявлено RDS без AV-збігу: 443
✅ Усі результати збережено до data/result/
--------------------------------------------
```

---

## ✅ Критерії прийняття
- [ ] Команда `python3 scripts/psh.py rds` створює всі п’ять файлів `rds-*.csv`.
- [ ] Логіка фільтрації повністю ідентична до обробки `dhcp-*.csv`.
- [ ] Формати CSV і шапки — однакові.
- [ ] Консольний вивід оформлений у тому ж стилі, що й для DHCP (українською).
- [ ] Вивід містить підсумкову лінію-роздільник.
