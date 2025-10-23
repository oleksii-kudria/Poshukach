# 🧩 Завдання 15 — Поділ обробки на два потоки: основний і мережевий

## 🎯 Мета
Розділити логіку обробки на два незалежні потоки, щоб основний процес виконував звичайну фільтрацію DHCP-записів, а додатковий — виявляв мережеві пристрої.

---

## 🔹 Потік A — Основний
Основна логіка залишається без змін і працює за схемою:

**random → ignore → перевірка MAC**

### Вихідні файли:
- `data/result/dhcp-random.csv` — усі записи, де `randomized == true`
- `data/result/dhcp-ignore.csv` — збіги з правилами з `configs/device_ignore.yml`
- `data/result/dhcp-true.csv` — MAC знайдено у `data/interim/mac.csv`
- `data/result/dhcp-false.csv` — MAC не знайдено у `data/interim/mac.csv`

> Потік A виконує основну логіку перевірки DHCP-записів, виявлення зареєстрованих пристроїв та ігнорування непотрібних.

---

## 🔷 Потік B — Мережеві пристрої
Додати окремий незалежний потік, який аналізує ті ж самі вхідні дані (`data/interim/dhcp.csv`) з метою **виявлення всіх мережевих пристроїв**, що відповідають правилам з `configs/device_network.yml`.

### Логіка роботи Потоку B:
1. Виконати другий прохід по файлу `data/interim/dhcp.csv`.
2. Завантажити правила з `configs/device_network.yml`.
3. Якщо будь-який рядок збігається з патерном — записати його у `data/result/dhcp-network.csv`.
4. За замовчуванням пропускати рядки, де `randomized == true`, щоб уникнути хибних збігів.

### Підтримувані режими в `configs/device_network.yml`:
- `prefix` — ім’я починається з патерну;
- `contains` — ім’я містить патерн;
- `regex` — частковий або повний збіг за регулярним виразом;
- `vendor` — збіг за полем `vendor` (порівняння без урахування регістру).

### Приклад файлу `configs/device_network.yml`:
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

---

## ⚙️ Порядок виконання
1. Запустити Потік A — основну логіку фільтрації (random → ignore → перевірка MAC).
2. Після завершення — окремо запустити Потік B для пошуку мережевих пристроїв.
3. Обидва потоки працюють незалежно, з окремими вихідними файлами у директорії `data/result/`.

> Потік B не впливає на результат Потоку A — один і той самий запис може одночасно потрапити у `dhcp-ignore.csv` і `dhcp-network.csv`.

---

## 📊 Очікуваний результат
Після запуску скрипта в консолі очікується приблизно такий підсумок:
```
🔹 randomized: 5
🟡 ignore: 12
✅ true: 84
⚠️ false: 31
🔷 network: 21
📁 data/result/{dhcp-random.csv, dhcp-ignore.csv, dhcp-true.csv, dhcp-false.csv, dhcp-network.csv}
```

---

## ✅ Критерії прийняття
- [ ] Потік A залишається без змін (random → ignore → перевірка MAC).  
- [ ] Потік B створює файл `data/result/dhcp-network.csv` за правилами з `configs/device_network.yml`.  
- [ ] Обидва потоки працюють незалежно й можуть запускатися послідовно.  
- [ ] Підтримується опція для включення randomized-записів у Потік B.  
- [ ] Формати всіх результатів ідентичні `data/interim/dhcp.csv`.
