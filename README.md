# RootScope — read-only scanner for iQOO Z10 Lite / OriginOS 6

Только сбор информации. Никаких попыток записи в память, ядро, TEE или partition.

## Что собирает (v1.1)

1. Полный Build / fingerprint / security patch
2. Kernel version + cmdline
3. SELinux status
4. Bootloader lock status + vbmeta details
5. Slot / A/B / dynamic partitions
6. Важные system properties (включая vivo/originos)
7. Проверка поддержки vivo unlock
8. Mounts
9. Наличие su/magisk путей
10. Типичные misconfig
11. Список потенциальных CVE под kernel 5.15
12. Краткий вывод

## Сборка через GitHub Actions (рекомендуется)

1. Создай репозиторий на GitHub
2. Загрузи содержимое этой папки в корень репозитория
3. Actions → Android APK → Run workflow
4. После успешной сборки скачай артефакт **android-debug-apk**

## Локальная сборка

```bash
./gradlew assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`

На Windows:
```cmd
gradlew.bat assembleDebug
```

## Права

- INTERNET
- QUERY_ALL_PACKAGES

Никаких WRITE_* и опасных runtime-permissions.
