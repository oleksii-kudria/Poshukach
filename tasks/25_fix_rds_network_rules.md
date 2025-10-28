# 🧩 Завдання 25 — Фікс порожнього `rds-network.csv` (device_network.yml для RDS)

## 🎯 Мета
Забезпечити коректне формування `data/result/rds-network.csv` під час запуску:
```bash
python3 scripts/psh.py rds
```
Наразі файл створюється, але **порожній**, попри наявність у `data/interim/rds.csv` записів з вендорами на кшталт **"TP-Link Systems Inc"**, **"TP-LINK TECHNOLOGIES CO.,LTD."**, **"Routerboard.com"** тощо.  
Необхідно:
1) виконувати **окремий прохід** по `device_network.yml` саме для RDS;  
2) **нормалізувати** поля `vendor` та **підтримати case-insensitive/regex** порівняння;  
3) правильно обробляти `require`/`except` (не блокувати все за замовчуванням).

---

## 🔧 Завдання

### 1) Окремий прохід (Потік B) для RDS
- Забезпечити виклик логіки **мережевих правил** для `data/interim/rds.csv`, незалежно від Потоку A (random → ignore → MAC).
- Не використовувати відфільтровану підмножину з Потоку A — **брати повний набір** рядків з `data/interim/rds.csv`.
- Результат записувати у **`data/result/rds-network.csv`** з шапкою ідентичною до `data/interim/rds.csv`.

### 2) Нормалізація вендора
- Перед матчингом нормалізувати обидві частини:
  - `vendor_norm = vendor.strip()` → зняти пробіли на краях;
  - прибрати фінальні `[,.;]` та подвоєні пробіли;
  - привести до нижнього регістру (`lower()`).
- Для `patterns` із `device_network.yml` виконувати порівняння **без урахування регістру**:
  - якщо елемент виглядає як звичайний текст → `pattern_norm in vendor_norm`;
  - якщо елемент заданий як regex → `re.search(pattern, vendor, re.IGNORECASE)`.

### 3) Підтримка `require` / `except`
- Якщо **`except`** (будь-який підпункт) спрацював → **правило не застосовувати**.
- Якщо **`require`** **присутній**, то **має спрацювати хоча б одна** умова з нього, інакше правило **не застосовувати**.
- Якщо `require` **відсутній** → зберегти **стару поведінку** (збіг по `vendor` достатній).
- Врахувати, що для RDS часто `name` може бути `unknown`, а `vendorClass` відсутній — **не робити `require` обовʼязковим** для всіх правил.

### 4) Базові правила для вендорів (рекомендація у `configs/device_network.yml`)
Додати/уточнити записи, щоб вони спрацьовували без `require` (для критичних брендів), або додати варіанти написання/regex:
```yaml
rules:
  - mode: vendor
    patterns:
      - "Routerboard.com"
      - "(?i)^mikrotik"             # альтернативне найменування
  - mode: vendor
    patterns:
      - "(?i)^tp[- ]?link"          # покриває TP-Link Systems Inc / TP-LINK TECHNOLOGIES CO.,LTD.
    # за потреби можна додати require/except для відсікання USB-адаптерів
```
> **Важливо:** якщо додаєш `require` для TP-Link (наприклад, `name_contains: ["Archer", "Deco"]`), переконайся, що для RDS він **може спрацювати**, або заведи **окреме** правило без `require`.

### 5) Логи підсумку (українською, короткі)
Відповідно до вимог Завдання 21 — **лише підсумки**:
```
🔧 Підсумок правил vendor (device_network.yml): застосовано=X, пропущено=Y (except=a, require=b)
✅ Обробку правил vendor завершено успішно.
```

---

## 🧪 Перевірка / Тести

1) **Саніті-тест**
   - Додати у `data/interim/rds.csv` рядок з `vendor="Routerboard.com"` → очікуємо потрапляння у `rds-network.csv`.
2) **TP-Link альтернативи**
   - Перевірити `vendor="TP-Link Systems Inc"` та `vendor="TP-LINK TECHNOLOGIES CO.,LTD."` → при базовому правилі без `require` мають потрапляти в сітку.
3) **Виключення (`except`)**
   - Якщо додані `except` для USB-адаптерів (через `oui_prefixes` або `name_regex`: `DESKTOP-`), перевірити, що ПК з адаптером **не** потрапляє у `rds-network.csv`.
4) **Незалежність від Потоку A**
   - Навіть якщо запис потрапив у `rds-ignore.csv` або `rds-random.csv`, перевірити, що **окремий** прохід для мережевих правил працює на **повному** наборі даних і коректно визначає мережеве обладнання (за бізнес-логікою твоєї системи — дозволено дублювання у `rds-network.csv` як окремий звітний зріз).

---

## 📋 Критерії прийняття
- [ ] `python3 scripts/psh.py rds` генерує **непорожній** `data/result/rds-network.csv` (за наявності відповідних вендорів).
- [ ] Матчинг `vendor` є **case-insensitive** і підтримує **regex**.
- [ ] `require`/`except` працюють згідно логіки вище, без тотального блокування записів.
- [ ] Прохід для `device_network.yml` виконується **окремо** від Потоку A і по **повному** `data/interim/rds.csv`.
- [ ] У консолі показано **стислий** український підсумок для правил vendor.

---

## 🧱 Підказки до реалізації (інтерфейс функцій)
- `load_rules("configs/device_network.yml") -> List[Rule]`
- `apply_network_rules(rows, rules) -> (matched_rows, counters)`
- `normalize_vendor(v: str) -> str` — обрізання пробілів, прибирання кінцевих знаків, `lower()`
- `match_vendor(vendor: str, patterns: List[str]) -> bool` — підтримка contains/regex (обидва case-insensitive)
- `require_hit(row, require_cfg) -> bool` — будь-який підпункт (name_contains/vendor_class*/oui_prefixes)
- `except_hit(row, except_cfg) -> bool` — будь-який підпункт
- Наприкінці: `write_csv("data/result/rds-network.csv", matched_rows)`
