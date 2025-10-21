# 🧩 Завдання 07 — Порівняння DHCP і AV-MAC списків

## 🎯 Мета
Зіставити MAC‑адреси з файлів `data/interim/dhcp.csv` та `data/interim/mac.csv`, визначити, які з них присутні у списку AV‑MAC, і розділити результати на два файли.

---

## 📁 Вхідні дані

### 1️⃣ `data/interim/dhcp.csv`
Файл має колонки:
```
source,ip,mac,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
```
- Обробляються **лише рядки, де `randomized == false`**.

### 2️⃣ `data/interim/mac.csv`
Файл має колонки:
```
mac,source
```
- Використовується **множина** значень `mac` для перевірки збігів.

---

## 📤 Вихідні файли

1. **`data/result/dhcp-true.csv`**  
   - Містить усі рядки з `dhcp.csv`, де `mac` знайдено у списку `mac.csv`.

2. **`data/result/dhcp-false.csv`**  
   - Містить рядки, де `mac` **не знайдено** у списку `mac.csv`.

> Обидва файли мають **ідентичний заголовок** до `data/interim/dhcp.csv`.

---

## ⚙️ Логіка виконання

1. Зчитати `data/interim/mac.csv` → створити множину `mac_set`.
2. Зчитати `data/interim/dhcp.csv`.
3. Пропустити всі рядки, де `randomized != false`.
4. Для кожного запису:
   - Якщо `mac` ∈ `mac_set` → додати рядок до `data/result/dhcp-true.csv`.
   - Інакше → до `data/result/dhcp-false.csv`.
5. Створити директорію `data/result/`, якщо її немає.
6. Записати заголовки (`header`) у обидва файли.
7. Після завершення вивести у консоль підсумок:
   ```
   ✅ DHCP збігів знайдено: <X>
   ⚠️ DHCP без збігів: <Y>
   📁 Результати збережено до data/result/dhcp-true.csv та data/result/dhcp-false.csv
   ```

---

## 🧱 Псевдокод
```python
import csv
from pathlib import Path

# 1. Зчитування mac.csv
mac_set = set()
with open("data/interim/mac.csv", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        mac_set.add(row["mac"])

# 2. Підготовка вихідних файлів
Path("data/result").mkdir(parents=True, exist_ok=True)
true_path = Path("data/result/dhcp-true.csv")
false_path = Path("data/result/dhcp-false.csv")

with open("data/interim/dhcp.csv", encoding="utf-8") as f_in,      open(true_path, "w", encoding="utf-8", newline="") as f_true,      open(false_path, "w", encoding="utf-8", newline="") as f_false:

    reader = csv.DictReader(f_in)
    headers = reader.fieldnames
    writer_true = csv.DictWriter(f_true, fieldnames=headers)
    writer_false = csv.DictWriter(f_false, fieldnames=headers)
    writer_true.writeheader()
    writer_false.writeheader()

    match_count, miss_count = 0, 0

    for row in reader:
        if row["randomized"].strip().lower() != "false":
            continue
        if row["mac"] in mac_set:
            writer_true.writerow(row)
            match_count += 1
        else:
            writer_false.writerow(row)
            miss_count += 1

print(f"✅ DHCP збігів знайдено: {match_count}")
print(f"⚠️ DHCP без збігів: {miss_count}")
print("📁 Результати збережено до data/result/dhcp-true.csv та data/result/dhcp-false.csv")
```

---

## ✅ Критерії прийняття
- [ ] Обробляються лише рядки з `randomized == false`.
- [ ] Створюються два результуючі файли: `dhcp-true.csv` і `dhcp-false.csv`.
- [ ] Формат і заголовки збігаються з `data/interim/dhcp.csv`.
- [ ] У консолі виводиться статистика по збігах і відсутніх адресах.
- [ ] Директорія `data/result/` створюється автоматично, якщо її немає.
