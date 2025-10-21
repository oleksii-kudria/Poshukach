# 🧩 Завдання 09 — Додавання файлу `data/result/dhcp-ignore.csv` для пристроїв з правил ігнорування

## 🎯 Мета
Оновити логіку з **Завдання 08**:  
тепер рядки, що відповідають правилам із `configs/device_ignore.yml`, **не ігноруються**, а **записуються до окремого CSV-файлу** `data/result/dhcp-ignore.csv`.

---

## 📁 Вхідні файли
1. `data/interim/dhcp.csv`
2. `data/interim/mac.csv`
3. `configs/device_ignore.yml`

---

## 📤 Вихідні файли

- `data/result/dhcp-true.csv` — збіг за MAC (як у Завданні 07).  
- `data/result/dhcp-false.csv` — MAC не знайдено.  
- 🆕 `data/result/dhcp-ignore.csv` — рядки, які підпадають під правила `device_ignore.yml`.

Усі три файли мають **однакову структуру**, як у `data/interim/dhcp.csv`.

---

## ⚙️ Оновлена логіка виконання

1. Зчитати `configs/device_ignore.yml` та побудувати список правил (`prefix`, `contains`, `regex`).
2. Для кожного рядка у `data/interim/dhcp.csv`:
   - Пропустити, якщо `randomized != false`.
   - Якщо `name` відповідає хоча б одному правилу:
     - додати рядок до `data/result/dhcp-ignore.csv`;
     - **не перевіряти MAC**.
   - Якщо не відповідає жодному правилу:
     - перевірити MAC (як у Завданні 07);
       - якщо знайдено — до `dhcp-true.csv`;
       - якщо ні — до `dhcp-false.csv`.
3. Усі файли мають заголовок (`header`) із `data/interim/dhcp.csv`.

---

## 📤 Приклад виводу
```
🟡 Ігноровано за правилами: 14
✅ DHCP збігів: 82
⚠️ DHCP без збігів: 29
📁 Результати збережено до data/result/dhcp-true.csv, dhcp-false.csv та dhcp-ignore.csv
```

---

## ✅ Критерії прийняття
- [ ] Рядки, що відповідають `device_ignore.yml`, зберігаються у `data/result/dhcp-ignore.csv`.  
- [ ] Формат усіх трьох файлів відповідає `data/interim/dhcp.csv`.  
- [ ] У консолі виводиться кількість рядків у кожному результаті.  
- [ ] Перевірка правил (`prefix`, `contains`, `regex`) виконується без урахування регістру.  
- [ ] MAC-перевірка **не виконується** для рядків, що потрапили в `dhcp-ignore.csv`.
