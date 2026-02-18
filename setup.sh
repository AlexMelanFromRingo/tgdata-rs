#!/usr/bin/env bash
set -e

echo "[setup] Создаём виртуальное окружение .venv ..."
python3 -m venv .venv

echo "[setup] Устанавливаем зависимости ..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt

echo "[setup] Применяем патч совместимости с новым Telegram Desktop ..."
.venv/bin/python patch_opentele.py

echo ""
echo "[OK] Готово! Теперь можно запускать:"
echo "  ./tg_acc_tool --path '/mnt/l/Programs/Telegram Desktop'"
echo "  или напрямую:"
echo "  .venv/bin/python tg_tool.py --path '/mnt/l/Programs/Telegram Desktop'"
