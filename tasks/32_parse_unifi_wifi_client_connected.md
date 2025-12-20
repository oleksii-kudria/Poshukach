# 🧩 Завдання 32 — Підтримка CEF подій UniFi `WiFi Client Connected`

## 🎯 Мета
Додати підтримку ще одного формату подій у файлах `data/raw/dhcp/*.csv`, які надходять у **CEF‑форматі від UniFi** та описують підключення Wi‑Fi клієнтів.

Такі записи **не є DHCP‑логами**, але містять корисну інформацію про:
- IP‑адресу клієнта
- MAC‑адресу пристрою
- Імʼя клієнтського пристрою

---

## 🧩 Приклад `payloadAsUTF`
```
Dec 19 16:48:34 UDM-001 CEF:0|Ubiquiti|UniFi Network|10.0.162|400|WiFi Client Connected|1|UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=UDM-001 UNIFIconnectedToDeviceName=room2 UNIFIconnectedToDeviceIp=192.168.1.11 UNIFIconnectedToDeviceMac=81:72:43:b4:d5:26 UNIFIconnectedToDeviceModel=U7-LR UNIFIconnectedToDeviceVersion=8.0.62 UNIFIclientAlias=User01. UNIFIclientHostname=iPhone UNIFIclientIp=192.168.21.154 UNIFIwifiChannel=157 UNIFIwifiChannelWidth=40 UNIFIwifiName=guest UNIFInetworkName=BudMac UNIFIutcTime=2025-12-19T14:48:34.790Z msg=User01 connected to guest on room2. Connection Info: Ch. 157 (5 GHz, 40 MHz), -65 dBm. IP: 192.168.21.154
```

---

## 📌 Ключова ознака формату
Наявність підрядка:
```
WiFi Client Connected
```

---

## ⚙️ Завдання

### 1) Детектор формату
- Якщо `payloadAsUTF` містить `CEF:` **та** `WiFi Client Connected` → застосувати парсер UniFi Wi‑Fi.

### 2) Парсинг полів

| Поле | Джерело |
|----|----|
| `ip` | `UNIFIclientIp` |
| `mac` | `UNIFIconnectedToDeviceMac` |
| `name` | `UNIFIclientHostname` |

### 3) Нормалізація
- `mac` → `XX:XX:XX:XX:XX:XX`
- `name` → `unknown`, якщо відсутній або порожній

### 4) Час
- Використати `UNIFIutcTime`, привести до `Europe/Kyiv`
- Якщо відсутній → fallback на `deviceTime`

### 5) Поведінка при помилках
```
⚠️ Неможливо розпарсити UniFi WiFi CEF рядок payloadAsUTF: <оригінальна строка>
```

### 6) Підсумок у консолі
```
✅ UniFi WiFi CEF подій оброблено: X
⚠️ UniFi WiFi CEF подій пропущено: Y
```

---

## ✅ Критерії прийняття
- [ ] Формат розпізнається стабільно
- [ ] Поля `ip`, `mac`, `name` коректні
- [ ] Час коректний (Kyiv)
- [ ] Інші формати не зламані
