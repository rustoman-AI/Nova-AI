#!/bin/bash

# Скрипт для сборки проекта (Frontend + Backend)
# Устанавливает зависимости и выполняет сборку релиза

echo "🚀 Начинаем сборку cyclonedx-tauri-ui..."

# 1. Установка npm зависимостей
echo "📦 Установка npm зависимостей..."
npm install

# 2. Сборка фронтенда (Vite/React)
echo "🖼️  Сборка фронтенда..."
npm run build

# 3. Сборка бэкенда (Rust/Tauri) в релизном профиле
echo "🦀 Сборка бэкенда (Rust)..."
# Вы можете использовать `npm run tauri build` для создания готового установщика (AppImage/deb/msi)
# или просто собрать бинарник Cargo:
cargo build --release --manifest-path src-tauri/Cargo.toml

echo "✅ Сборка успешно завершена!"
