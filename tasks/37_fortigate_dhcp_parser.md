# TASK-037: Додати підтримку FortiGate DHCP event logs у `data/raw/dhcp/*.csv`

## Контекст
У проєкті вже підтримується обробка кількох типів DHCP / log-джерел у директорії:

`data/raw/dhcp/*.csv`

Поточна логіка повинна бути розширена так, щоб на вхід міг подаватися також CSV-файл з журналами подій FortiGate (DHCP ACK).

---

## Що потрібно зробити

Додати підтримку нового типу вхідних даних:
- FortiGate DHCP event logs

---

## Формат вхідних даних

Приклад CSV:

"Device Name (custom)","Start Time","Log Source Identifier",
"FG123123","Apr 8, 2026, 11:01:51 AM","10.10.10.10","<190>logver=706063652 ... mac="22:22:22:33:33:77" ip="172.17.0.5" hostname="Mikrotik" ..."

---

## Правила обробки

### 1. Визначення формату
Ознаки FortiGate:
- поле `Start Time`
- поле `Log Source Identifier`
- payload містить `logdesc="DHCP Ack log"`

---

### 2. Час
- використовувати `Start Time`
- привести до epoch відповідно до існуючої логіки

---

### 3. Джерело
- `Log Source Identifier` = IP джерела

---

### 4. Парсинг payload
Необхідно витягнути:
- mac
- ip
- hostname

Формат:
mac="XX:XX:XX:XX:XX:XX"
ip="X.X.X.X"
hostname="device"

---

### 5. payload колонка
Може бути:
- `payloadAsUTF`
- без назви

Потрібно підтримати обидва варіанти

---

### 6. Нормалізація
Привести до стандартної структури:
- timestamp
- source_ip
- mac
- ip
- name
- payload

---

### 7. Pipeline
Далі обробка стандартна:
- validate
- collect
- normalize
- diff
- report

---

## Важливі вимоги

- не ламати існуючі формати
- універсальний підхід
- коректна обробка пустого header
- нормалізація MAC

---

## Результат

- підтримка FortiGate DHCP logs
- коректний парсинг payload
- інтеграція в pipeline
- додані приклади:
  data/raw/data.fortigate.example.csv
