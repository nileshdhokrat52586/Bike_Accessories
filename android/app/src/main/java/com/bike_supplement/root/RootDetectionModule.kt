package com.yourapp.root

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class RootDetectionModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    override fun getName(): String = "RootDetection"

    @ReactMethod
    fun isDeviceRooted(promise: Promise) {
        try {
            val rooted = isRooted(reactContext)
            promise.resolve(rooted)
        } catch (e: Exception) {
            promise.reject("ROOT_CHECK_ERROR", e)
        }
    }

    companion object {
        // High-level check: run several heuristics
        fun isRooted(context: Context): Boolean {
            return checkRootMethods()
                || checkForSuBinary()
                || checkForDangerousProps()
                || checkForRWPaths()
                || checkForRootPackages(context)
                || checkForMagisk()
        }

        private fun checkRootMethods(): Boolean {
            // Common file locations
            val paths = arrayOf(
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su"
            )
            for (path in paths) {
                if (File(path).exists()) return true
            }
            return false
        }

        private fun checkForSuBinary(): Boolean {
            return try {
                // try "which su"
                val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val output = reader.readLine()
                reader.close()
                !output.isNullOrEmpty()
            } catch (t: Throwable) {
                false
            }
        }

        private fun checkForMagisk(): Boolean {
            // Magisk commonly leaves these hints
            val magiskPaths = arrayOf(
                "/sbin/magisk",
                "/sbin/.magisk",
                "/system/bin/.magisk",
                "/system/xbin/magisk"
            )
            for (p in magiskPaths) if (File(p).exists()) return true

            // Also check for magisk manager package name (may vary)
            // (we do package check elsewhere too)
            return false
        }

        private fun checkForDangerousProps(): Boolean {
            return try {
                val tags = Build.TAGS
                if (tags != null && tags.contains("test-keys")) return true

                // check ro.debuggable or ro.secure via getprop (best-effort)
                val getprop = Runtime.getRuntime().exec("getprop ro.debuggable")
                val reader = BufferedReader(InputStreamReader(getprop.inputStream))
                val valDbg = reader.readLine()
                reader.close()
                if (!valDbg.isNullOrEmpty() && valDbg.trim() == "1") return true

                val getprop2 = Runtime.getRuntime().exec("getprop ro.secure")
                val reader2 = BufferedReader(InputStreamReader(getprop2.inputStream))
                val valSec = reader2.readLine()
                reader2.close()
                if (!valSec.isNullOrEmpty() && valSec.trim() == "0") return true

                false
            } catch (t: Throwable) {
                false
            }
        }

        private fun checkForRWPaths(): Boolean {
            // try writing to /data or / (usually not allowed on non-root)
            return try {
                val testFile = File("/data/local/tmp/__rtest")
                if (testFile.exists()) { testFile.delete(); true }
                else {
                    val created = testFile.createNewFile()
                    if (created) {
                        testFile.delete()
                        true
                    } else false
                }
            } catch (e: Throwable) {
                // failure is expected on non-rooted devices
                false
            }
        }

        private fun checkForRootPackages(context: Context): Boolean {
            val pm = context.packageManager
            val packagesToCheck = arrayOf(
                "com.noshufou.android.su",
                "com.thirdparty.superuser",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.topjohnwu.magisk" // Magisk Manager
            )
            for (pkg in packagesToCheck) {
                try {
                    pm.getPackageInfo(pkg, 0)
                    return true
                } catch (ignored: PackageManager.NameNotFoundException) {
                }
            }
            return false
        }
    }
}
