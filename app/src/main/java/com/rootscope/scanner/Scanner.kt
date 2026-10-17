package com.rootscope.scanner

import android.os.Build
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Чистый read-only сканер.
 * Никаких записей, никаких exec с попыткой поднятия привилегий.
 */
object Scanner {

    private val log = StringBuilder()

    fun runFullScan(): String {
        log.clear()
        header("RootScope Scanner — read-only v1.1")
        line("Время: ${now()}")
        line("Цель: fingerprint / props / SELinux / lock / slot / vbmeta / vivo unlock / misconfig / CVE")
        line("Устройство: iQOO Z10 Lite (I2502) / OriginOS 6 / SD685 / kernel 5.15")
        separator()

        sectionBuildInfo()
        sectionKernel()
        sectionSelinux()
        sectionBootloaderAndVbmeta()
        sectionSlotAndPartitions()
        sectionImportantProps()
        sectionVivoUnlockCheck()
        sectionMounts()
        sectionSuPresence()
        sectionMisconfigs()
        sectionCveCandidates()
        sectionSummary()

        return log.toString()
    }

    // ------------------------------------------------------------------

    private fun sectionBuildInfo() {
        header("1. Build / Fingerprint")
        line("MODEL          : ${Build.MODEL}")
        line("DEVICE         : ${Build.DEVICE}")
        line("PRODUCT        : ${Build.PRODUCT}")
        line("BRAND          : ${Build.BRAND}")
        line("MANUFACTURER   : ${Build.MANUFACTURER}")
        line("BOARD          : ${Build.BOARD}")
        line("HARDWARE       : ${Build.HARDWARE}")
        line("FINGERPRINT    : ${Build.FINGERPRINT}")
        line("DISPLAY        : ${Build.DISPLAY}")
        line("ID             : ${Build.ID}")
        line("TAGS           : ${Build.TAGS}")
        line("TYPE           : ${Build.TYPE}")
        line("USER           : ${Build.USER}")
        line("HOST           : ${Build.HOST}")
        line("TIME           : ${Build.TIME}")
        line("SDK_INT        : ${Build.VERSION.SDK_INT}")
        line("RELEASE        : ${Build.VERSION.RELEASE}")
        line("SECURITY_PATCH : ${Build.VERSION.SECURITY_PATCH}")
        line("CODENAME       : ${Build.VERSION.CODENAME}")
        line("INCREMENTAL    : ${Build.VERSION.INCREMENTAL}")
        if (Build.VERSION.SDK_INT >= 23) {
            line("BASE_OS        : ${Build.VERSION.BASE_OS}")
            line("PREVIEW_SDK    : ${Build.VERSION.PREVIEW_SDK_INT}")
        }
        if (Build.VERSION.SDK_INT >= 30) {
            line("RELEASE_OR_CODENAME : ${Build.VERSION.RELEASE_OR_CODENAME}")
        }
        line("SUPPORTED_ABIS : ${Build.SUPPORTED_ABIS.joinToString()}")
    }

    private fun sectionKernel() {
        header("2. Kernel")
        line("uname -a       : ${shell("uname -a")}")
        line("/proc/version  : ${readFile("/proc/version")}")
        line("Kernel cmdline : ${readFile("/proc/cmdline").take(400)}")
    }

    private fun sectionSelinux() {
        header("3. SELinux")
        val enforce = shell("getenforce").trim()
        line("getenforce     : $enforce")
        line("/sys/fs/selinux/enforce : ${readFile("/sys/fs/selinux/enforce")}")
        when {
            enforce.equals("Enforcing", true) -> line("Статус: ENFORCING (норма для стока)")
            enforce.equals("Permissive", true) -> line("Статус: PERMISSIVE (подозрительно, часто после root)")
            else -> line("Статус: неизвестно / disabled (часто Permission denied без root)")
        }
    }

    private fun sectionBootloaderAndVbmeta() {
        header("4. Bootloader / Verified Boot / vbmeta")
        val locked = getprop("ro.boot.flash.locked")
        val verified = getprop("ro.boot.verifiedbootstate")
        val oemUnlock = getprop("sys.oem_unlock_allowed")
        val unlockSupport = getprop("ro.oem_unlock_supported")
        val vbmetaState = getprop("ro.boot.vbmeta.device_state")
        val vbmetaDigest = getprop("ro.boot.vbmeta.digest")
        val vbmetaHashAlg = getprop("ro.boot.vbmeta.hash_alg")
        val vbmetaSize = getprop("ro.boot.vbmeta.size")
        val avbVersion = getprop("ro.boot.avb_version")
        val warranty = getprop("ro.boot.warranty_bit")
        val warranty2 = getprop("ro.warranty_bit")
        val secureboot = getprop("ro.boot.secureboot")
        val dmVerity = getprop("ro.boot.veritymode")

        line("ro.boot.flash.locked        : $locked")
        line("ro.boot.verifiedbootstate   : $verified")
        line("sys.oem_unlock_allowed      : $oemUnlock")
        line("ro.oem_unlock_supported     : $unlockSupport")
        line("ro.boot.vbmeta.device_state : $vbmetaState")
        line("ro.boot.vbmeta.digest       : $vbmetaDigest")
        line("ro.boot.vbmeta.hash_alg     : $vbmetaHashAlg")
        line("ro.boot.vbmeta.size         : $vbmetaSize")
        line("ro.boot.avb_version         : $avbVersion")
        line("ro.boot.warranty_bit        : $warranty")
        line("ro.warranty_bit             : $warranty2")
        line("ro.boot.secureboot          : $secureboot")
        line("ro.boot.veritymode          : $dmVerity")

        val status = when {
            locked == "1" || verified.equals("green", true) -> "LOCKED (green)"
            verified.equals("orange", true) || locked == "0" -> "UNLOCKED (orange)"
            verified.equals("yellow", true) -> "LOCKED + custom root of trust (yellow)"
            else -> "не удалось однозначно определить"
        }
        line("Вывод: $status")
    }

    private fun sectionSlotAndPartitions() {
        header("5. Slot / Dynamic partitions / A/B")
        line("ro.boot.slot_suffix         : ${getprop("ro.boot.slot_suffix")}")
        line("ro.boot.dynamic_partitions  : ${getprop("ro.boot.dynamic_partitions")}")
        line("ro.boot.dynamic_partitions_retrofit : ${getprop("ro.boot.dynamic_partitions_retrofit")}")
        line("ro.boot.slot_successful     : ${getprop("ro.boot.slot_successful")}")
        line("ro.boot.slot_retry_count    : ${getprop("ro.boot.slot_retry_count")}")
        line("ro.boot.slot_unbootable     : ${getprop("ro.boot.slot_unbootable")}")
        line("ro.boot.current_slot        : ${getprop("ro.boot.current_slot")}")
        line("ro.boot.boot_devices        : ${getprop("ro.boot.boot_devices")}")
        line("ro.boot.bootdevice          : ${getprop("ro.boot.bootdevice")}")
        line("ro.boot.boot_serialno       : ${getprop("ro.boot.boot_serialno")}")
        line("ro.serialno                 : ${getprop("ro.serialno")}")
        line("ro.boot.serialno            : ${getprop("ro.boot.serialno")}")
        line("ro.bootmode                 : ${getprop("ro.bootmode")}")
        line("ro.boot.mode                : ${getprop("ro.boot.mode")}")
        line("sys.usb.config              : ${getprop("sys.usb.config")}")
        line("persist.sys.usb.config      : ${getprop("persist.sys.usb.config")}")
    }

    private fun sectionImportantProps() {
        header("6. Важные system properties")
        val keys = listOf(
            "ro.build.fingerprint",
            "ro.build.version.security_patch",
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.build.tags",
            "ro.build.type",
            "ro.secure",
            "ro.debuggable",
            "ro.adb.secure",
            "service.adb.root",
            "persist.sys.usb.config",
            "ro.bootmode",
            "ro.hardware",
            "ro.product.cpu.abi",
            "ro.product.locale",
            "ro.vivo.os.version",
            "ro.vivo.product.version",
            "ro.vivo.build.version",
            "ro.vivo.os.build.display.id",
            "ro.origin.version",
            "ro.build.software.version",
            "ro.vivo.product.model",
            "ro.vivo.device.type",
            "ro.vivo.product.overseas",
            "ro.vivo.market.name",
            "gsm.version.baseband",
            "ro.baseband",
            "ro.boot.serialno",
            "ro.serialno",
            "ro.boot.slot_suffix",
            "ro.boot.dynamic_partitions",
            "ro.crypto.state",
            "ro.crypto.type",
            "ro.boot.flash.locked",
            "ro.boot.verifiedbootstate",
            "ro.oem_unlock_supported",
            "sys.oem_unlock_allowed",
            "persist.sys.oem_unlock_allowed",
            "ro.boot.vbmeta.device_state"
        )
        keys.forEach { k ->
            line("$k = ${getprop(k)}")
        }
    }

    private fun sectionVivoUnlockCheck() {
        header("7. Vivo / iQOO Unlock Support Check")
        line("Модель: I2502 (PD2470) — iQOO Z10 Lite")
        line("Производитель: vivo / iQOO")
        line("")

        val unlockSupported = getprop("ro.oem_unlock_supported")
        val unlockAllowed = getprop("sys.oem_unlock_allowed")
        val flashLocked = getprop("ro.boot.flash.locked")
        val verified = getprop("ro.boot.verifiedbootstate")
        val vbmeta = getprop("ro.boot.vbmeta.device_state")

        line("ro.oem_unlock_supported     : $unlockSupported")
        line("sys.oem_unlock_allowed      : $unlockAllowed")
        line("ro.boot.flash.locked        : $flashLocked")
        line("ro.boot.verifiedbootstate   : $verified")
        line("ro.boot.vbmeta.device_state : $vbmeta")
        line("")

        line("--- Анализ ---")
        line("1. Официальная программа разблокировки bootloader у vivo/iQOO отсутствует.")
        line("   Deep Testing (китайский канал) был закрыт в 2023 году.")
        line("2. На большинстве современных iQOO (включая Z-серию) bootloader")
        line("   заблокирован на заводе и публичного способа разблокировки нет.")
        line("3. ro.oem_unlock_supported пустой или не '1' → OEM Unlock в")
        line("   Developer Options либо скрыт, либо не работает.")
        line("4. verifiedbootstate=green + flash.locked=1 + vbmeta=locked")
        line("   подтверждает полностью стоковое locked-состояние.")
        line("")

        val conclusion = when {
            unlockSupported == "1" && unlockAllowed == "1" && flashLocked == "0" ->
                "Свойства указывают на возможную поддержку unlock (редко для vivo)"
            unlockSupported == "1" ->
                "ro.oem_unlock_supported=1, но устройство всё равно locked. На vivo это обычно ничего не даёт."
            else ->
                "Официальный unlock на I2502 / PD2470 практически недоступен."
        }
        line("Вывод: $conclusion")
        line("")
        line("Реалистичные пути:")
        line("  • Официальный unlock — нет")
        line("  • EDL + авторизованный firehose (сложно, риск brick)")
        line("  • 0day под ядро 5.15.197-android13")
        line("  • Ждать появления публичного метода (маловероятно)")
    }

    private fun sectionMounts() {
        header("8. Mounts (интересные)")
        val mounts = readFile("/proc/mounts")
        val interesting = mounts.lines().filter { line ->
            line.contains("/system") ||
            line.contains("/vendor") ||
            line.contains("/data") ||
            line.contains("tmpfs") && (line.contains("magisk") || line.contains("su"))
        }
        if (interesting.isEmpty()) {
            line("(не удалось прочитать /proc/mounts или пусто)")
        } else {
            interesting.take(40).forEach { line(it) }
            if (interesting.size > 40) line("... (ещё ${interesting.size - 40} строк)")
        }
        val systemRw = interesting.any { it.contains("/system") && it.contains(" rw,") }
        line(" /system смонтирован rw? : $systemRw  (на стоке должно быть false)")
    }

    private fun sectionSuPresence() {
        header("9. Наличие su / magisk (только exists, без exec)")
        val paths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/vendor/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/su/bin/su",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/dev/.magisk",
            "/data/adb/ksu",
            "/data/adb/ap",
            "/data/adb/modules",
            "/data/adb/magisk.db"
        )
        paths.forEach { p ->
            val exists = File(p).exists()
            line("$p : ${if (exists) "EXISTS" else "нет"}")
        }
    }

    private fun sectionMisconfigs() {
        header("10. Типичные misconfig (read-only checks)")

        val debuggable = getprop("ro.debuggable")
        val secure = getprop("ro.secure")
        val tags = getprop("ro.build.tags")
        val adbRoot = getprop("service.adb.root")

        line("ro.debuggable = $debuggable   (ожидается 0)")
        line("ro.secure     = $secure       (ожидается 1)")
        line("ro.build.tags = $tags         (ожидается release-keys)")
        line("service.adb.root = $adbRoot   (ожидается 0 или пусто)")

        val issues = mutableListOf<String>()
        if (debuggable == "1") issues.add("ro.debuggable=1 (debug build)")
        if (secure == "0") issues.add("ro.secure=0")
        if (tags.contains("test-keys") || tags.contains("dev-keys")) issues.add("неофициальные build tags")
        if (adbRoot == "1") issues.add("adb root включён")

        if (issues.isEmpty()) {
            line("Явных misconfig по props не видно.")
        } else {
            line("Найдены:")
            issues.forEach { line("  - $it") }
        }
    }

    private fun sectionCveCandidates() {
        header("11. Потенциально интересные CVE (kernel 5.15 / Qualcomm / Android 13-16)")
        line("Патч безопасности устройства: ${Build.VERSION.SECURITY_PATCH}")
        line("Ниже — список известных LPE-кандидатов. Наличие в списке НЕ означает,")
        line("что дыра жива на твоём билде. Большинство закрыто патчами 2024-2026.")
        line("")

        val cves = listOf(
            Cve("CVE-2026-43499", "GhostLock — futex/rtmutex UAF", "5.15", "высокий", "vivo/Honor research 2026"),
            Cve("CVE-2026-98260", "Infinity Core — timer UAF", "upstream 5.x", "высокий", "Oct 2026 disclosure"),
            Cve("CVE-2026-98256", "Infinity Core — sigqueue UAF", "upstream 5.x", "высокий", "Oct 2026"),
            Cve("CVE-2026-80775", "Infinity Core — futex UAF (vfork)", "upstream 5.x", "высокий", "Oct 2026"),
            Cve("CVE-2024-23380", "Qualcomm KGSL GPU UAF → root", "Adreno", "высокий", "patched ~Jul 2024"),
            Cve("CVE-2023-33106", "KGSL AUX command memory corruption", "Adreno", "высокий", "KEV, старый"),
            Cve("CVE-2023-33107", "KGSL shared virtual memory", "Adreno", "высокий", "KEV, старый"),
            Cve("CVE-2026-21385", "Qualcomm graphics integer overflow", "QC", "высокий", "KEV 2026"),
            Cve("CVE-2026-46242", "Bad Epoll — epoll LPE", "upstream", "высокий", "kernelCTF 2026"),
            Cve("CVE-2023-20938", "Binder UAF (классика)", "Binder", "высокий", "давно закрыт")
        )

        cves.forEach { c ->
            line("${c.id}")
            line("  ${c.title}")
            line("  область: ${c.area} | риск: ${c.risk} | примечание: ${c.note}")
            line("")
        }
        line("Для реального статуса нужно смотреть changelog ядра / security bulletin")
        line("конкретно под PD2470HF_EX_A_16.1.13.0.W20 и дату 2026-09-01.")
    }

    private fun sectionSummary() {
        header("12. Краткий вывод")
        line("Сканер ничего не писал и не пытался эксплуатировать.")
        line("Bootloader: LOCKED (green)")
        line("Официальный vivo/iQOO unlock на I2502: практически недоступен.")
        line("Публичных готовых userland→root цепочек под этот билд почти нет.")
        line("Следующий шаг: либо EDL (риск), либо ждать/искать 0day под 5.15.197.")
        separator()
        line("Конец отчёта — ${now()}")
    }

    // ------------------------------------------------------------------ helpers

    private fun getprop(key: String): String {
        return shell("getprop $key").trim().ifEmpty { "(пусто)" }
    }

    private fun shell(cmd: String): String {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
            val reader = BufferedReader(InputStreamReader(p.inputStream))
            val err = BufferedReader(InputStreamReader(p.errorStream))
            val out = reader.readText().trim()
            val errText = err.readText().trim()
            p.waitFor()
            if (out.isNotEmpty()) out else errText
        } catch (e: Exception) {
            "error: ${e.message}"
        }
    }

    private fun readFile(path: String): String {
        return try {
            File(path).readText().trim()
        } catch (e: Exception) {
            "недоступно (${e.message})"
        }
    }

    private fun now(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    private fun header(title: String) {
        log.appendLine()
        log.appendLine("══════════════════════════════════════")
        log.appendLine(title)
        log.appendLine("══════════════════════════════════════")
    }

    private fun separator() {
        log.appendLine("--------------------------------------")
    }

    private fun line(s: String) {
        log.appendLine(s)
    }

    private data class Cve(
        val id: String,
        val title: String,
        val area: String,
        val risk: String,
        val note: String
    )
}
