# dsh-plugin-antigravity-quota

Плагин для **DeepSeek Harness (DSH)**, обеспечивающий стабильную работу с моделями **Google AI Pro (Gemini 3.8 Flash, Claude и др.)** из РФ через локальный мост, DNS/SNI туннели и поддержку **GeoHide Smart DNS**.

---

## 🚀 Возможности
- **Мониторинг квот и аккаунтов**: виджет в интерфейсе DSH для отслеживания лимитов токенов и переключения аккаунтов.
- **Интеллектуальная маршрутизация Cloud Code**:
  - **GeoHide EU Smart DNS** (https://eu.geohide.ru/dns-query) — приоритетный маршрут в режиме Auto с европейским выходом (проверено: успешная генерация HTTP 200).
  - **GeoHide US Smart DNS** (https://us.geohide.ru/dns-query) — резервный маршрут Smart DNS.
  - **Обычные DoH-резолверы** (Comss.one, Router Comss, Bezmezhau, WLRUS) — резервные DNS-серверы.
- **Локальный защищенный мост**:
  - Порт 53130 — основной входящий CONNECT bridge.
  - Порт 53129 — совместимый listener.
  - Порт 8317 — локальный сервис cli-proxy-api.exe.
  - Порт 43129 — динамический локальный g_dns.
- **Защита от сбоев и автовосстановление**:
  - Автоматическое исключение узлов при региональных ошибках 400 location-not-supported или TLS-сбоях.
  - Стабильный процесс моста без ложных перезапусков сторожевым таймером.
  - Раздельные негенерационные тесты (DNS/TLS) для EU и US серверов без расхода квоты.

---

## 📦 Установка и обновление

### Вариант 1. Установка из готового архива (Рекомендуется)
1. Скачайте актуальный релизный архив dsh-plugin-antigravity-quota-1.5.1.tgz (или .zip) со страницы [Releases](../../releases).
2. Полностью закройте **DeepSeek Harness**.
3. Распакуйте содержимое архива в каталог плагина вашего профиля DSH:
   `	ext
   C:\Users\<Ваш_Пользователь>\.dsh\profiles\desktop\node_modules\dsh-plugin-antigravity-quota
   `
4. Убедитесь, что в файле C:\Users\<Ваш_Пользователь>\.dsh\profiles\desktop\package.json плагин указан в секциях dependencies и dsh.profile.bundles:
   `json
   "dependencies": {
     "dsh-plugin-antigravity-quota": "^1.5.1"
   },
   "dsh": {
     "profile": {
       "bundles": [
         "dsh-plugin-antigravity-quota"
       ]
     }
   }
   `
5. Запустите DeepSeek Harness. Виджет квот и маршрутов появится в правом нижнем углу интерфейса чата.

---

### Вариант 2. Автоматическое обновление через скрипт
В папке плагина есть готовый безопасный скрипт установки:
`powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "bin\install-active-profile.ps1"
`
Скрипт автоматически создаст резервную копию текущего плагина с датой и временем, проверит файлы и обновит активный профиль.

---

## 🛠️ Диагностика и проверка статуса

Для быстрой проверки здоровья моста и портов выполните:
`powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "bin\diagnose-routing.ps1"
`
Скрипт проверяет:
- Согласованность proxy-url: http://127.0.0.1:53130 в config.yaml и auth-файлах;
- Принадлежность портов 53130, 53129, 8317 и 43129;
- Текущий активный транспорт и порядок перебора в Auto;
- Не выводит OAuth-токены, пароли и личные данные.

---

## 🛡️ Безопасность
- Никакие токены, ключи API или идентификаторы аккаунтов Google не зашиты в репозиторий.
- Мост не выполняет MITM и сохраняет сквозное TLS-шифрование с серверами Google API.