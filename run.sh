#!/bin/bash

# Скрипт для запуска сервера разработки (Hot Reload для React + Cargo)

echo "🚀 Запуск cyclonedx-tauri-ui в режиме разработки..."

# Убедимся, что зависимости установлены
if [ ! -d "node_modules" ]; then
    echo "📦 node_modules не найдены. Выполняю npm install..."
    npm install
fi

# Запуск Tauri Dev
npm run tauri dev
