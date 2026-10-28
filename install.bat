@echo off
chcp 65001 >nul
echo [dsh-plugin-antigravity-quota] Запуск установки плагина в профиль DSH...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\install-active-profile.ps1"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [УСПЕШНО] Плагин установлен и зарегистрирован! Перезапустите DeepSeek Harness.
) else (
    echo.
    echo [ОШИБКА] Установка не удалась. Закройте DeepSeek Harness и попробуйте снова.
)
pause
