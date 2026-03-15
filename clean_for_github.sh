#!/bin/bash

# Скрипт для глубокой очистки проекта перед переносом на GitHub.
# Удаляет все временные файлы, кэши, установленные пакеты и скомпилированные бинарники.

echo "🧹 Очистка проекта cyclonedx-tauri-ui..."

# 1. Очистка frontend-зависимостей и кэшей сборки
echo "Удаление node_modules и папок frontend-сборки..."
rm -rf node_modules
rm -rf dist
rm -rf build

# Опционально: можно также удалить lock-файлы, если вы хотите, чтобы они сгенерировались заново на CI:
# rm -f package-lock.json

# 2. Очистка backend-кэшей сборки (Rust)
echo "Удаление src-tauri/target..."
rm -rf src-tauri/target

# Опционально: можно удалить Cargo.lock
# rm -f src-tauri/Cargo.lock

# 3. Устранение возможных системных файлов
echo "Удаление системных файлов (например, .DS_Store)..."
find . -name ".DS_Store" -type f -delete

echo "✨ Очистка завершена! Проект готов к инициализации git и переносу на GitHub."
echo "💡 Чтобы загрузить проект на GitHub, используйте следующие команды:"
echo "git init"
echo "git add ."
echo "git commit -m \"Initial commit\""
echo "git branch -M main"
echo "git remote add origin <URL_ВАШЕГО_РЕПОЗИТОРИЯ_В_GITHUB>"
echo "git push -u origin main"
