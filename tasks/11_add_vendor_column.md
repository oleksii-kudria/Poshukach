# 🧩 Завдання 11 — Додати стовпчик `vendor` до `data/interim/dhcp.csv`

## 🎯 Мета
Під час формування файлу `data/interim/dhcp.csv` (див. завдання 03–10) додати новий стовпчик **`vendor`** і заповнювати його назвою виробника, визначеною за OUI з файлу `data/cache/oui.csv`.  
Значення береться з поля **`Organization Name`** (офіційний CSV IEEE OUI).

---

## 📁 Вхідні дані
- `data/cache/oui.csv` — офіційний OUI-довідник (див. завдання 10). Типова структура:
  ```csv
  Registry,Assignment,Organization Name,Organization Address
  MA-L,F0-3E-90,Apple, Inc.,One Apple Park Way\nCupertino CA 95014\nUS
  MA-L,DC-A6-32,Samsung Electronics Co.,Ltd,129, Samsung-ro,...
  ...
  ```

- `data/interim/dhcp.csv` — формується скриптом з попередніх задач:
  ```csv
  source,ip,mac,vendor,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
  ```

---

## 🧩 Правила заповнення `vendor`
1. Для кожного рядка `dhcp.csv` визначити **OUI-префікс** з MAC — перші 6 шістнадцяткових символів (без розділювачів).  
   Приклад: `AA:BB:CC:DD:EE:FF` → OUI = `AABBCC`.
2. У `oui.csv` знайти збіг у полі **`Assignment`** (нормалізувати: забрати `-`, привести до верхнього регістру).  
   - Якщо знайдено — взяти **`Organization Name`** і записати в `vendor`.
   - Якщо не знайдено — записати `unknown`.
3. Для MAC з локально адміністрованим бітом (randomized/U/L bit = 1) **дозволено** залишати `vendor = ""` або `unknown` — **оберіть `unknown`** для однорідності.
4. Поле `vendor` **не впливає** на розподіл у `dhcp-true.csv` / `dhcp-false.csv` / `dhcp-ignore.csv` (це лише збагачення).

---

## 🧰 Зміни у структурі CSV
Рекомендоване розташування стовпчика: **після `mac`** (для зручності читання).
```
source,ip,mac,vendor,name,firstDate,lastDate,firstDateEpoch,lastDateEpoch,count,randomized,dateList
```

> Якщо у вас вже є стабільні споживачі цього CSV — узгодьте зміну порядку колонок. За потреби можна додати `vendor` у кінець.

---

## ✅ Критерії прийняття
- [ ] До `data/interim/dhcp.csv` додано стовпчик **`vendor`**.
- [ ] Для відомих OUI у полі `vendor` записується значення **`Organization Name`** з `oui.csv`.
- [ ] Для невідомих / локально адміністрованих MAC → `vendor = "unknown"`.
- [ ] Порядок колонок містить `vendor` (після `mac`, або у кінці — за узгодженням).
- [ ] Виводиться зрозуміле попередження, якщо `data/cache/oui.csv` відсутній.
