@echo off
echo [setup] Создаём виртуальное окружение .venv ...
python -m venv .venv
if errorlevel 1 (
    echo [ERROR] python не найден или недоступен. Установите Python 3.9+
    exit /b 1
)

echo [setup] Устанавливаем зависимости ...
.venv\Scripts\pip install --upgrade pip -q
.venv\Scripts\pip install -r requirements.txt

echo [setup] Применяем патч совместимости с новым Telegram Desktop ...
.venv\Scripts\python patch_opentele.py

echo.
echo [OK] Готово! Теперь можно запускать:
echo   tg_acc_tool.exe --path "L:\Programs\Telegram Desktop"
echo   или напрямую:
echo   .venv\Scripts\python tg_tool.py --path "L:\Programs\Telegram Desktop"
