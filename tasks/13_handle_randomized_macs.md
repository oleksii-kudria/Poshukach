# 🧩 Завдання 13 — Винесення randomized MAC-адрес у `data/result/dhcp-random.csv`

## 🎯 Мета
Під час формування вихідних файлів у директорії `data/result/` необхідно **окремо зберігати всі рядки**, де у полі `randomized == true`.  
Такі записи **не перевіряються на MAC-відповідність** і **не потрапляють до інших файлів (`dhcp-true.csv`, `dhcp-false.csv`, `dhcp-ignore.csv`)**.

---

## 📁 Вхідні дані
- `data/interim/dhcp.csv`  
  Містить колонку:
  ```csv
  source,ip,mac,vendor,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
  ```

---

## 📤 Вихідні файли
- `data/result/dhcp-random.csv` — усі рядки, де `randomized == true`.
- Інші файли (`dhcp-true.csv`, `dhcp-false.csv`, `dhcp-ignore.csv`) **не повинні** містити такі рядки.

---

## ⚙️ Логіка виконання

1. Відкрити `data/interim/dhcp.csv` і створити `csv.DictReader`.
2. Підготувати новий файл `data/result/dhcp-random.csv` із таким самим заголовком (`header`).
3. Для кожного рядка:
   - Якщо `randomized.strip().lower() == "true"` → записати у `dhcp-random.csv`.
   - Якщо `randomized.strip().lower() == "false"` → передати у звичайну логіку перевірок (як у Завданнях 07–12).
4. У кінці вивести статистику у консоль:
   ```
   🔹 Випадкових MAC-адрес виявлено: <X>
   📁 Збережено до data/result/dhcp-random.csv
   ```

---

## ✅ Критерії прийняття
- [ ] Усі рядки з `randomized == true` записуються до `data/result/dhcp-random.csv`.
- [ ] Такі рядки **не потрапляють** до `dhcp-true.csv`, `dhcp-false.csv`, `dhcp-ignore.csv`.
- [ ] Формат файлу (`header`) ідентичний `data/interim/dhcp.csv`.
- [ ] Виводиться статистика у консоль із кількістю рядків.
