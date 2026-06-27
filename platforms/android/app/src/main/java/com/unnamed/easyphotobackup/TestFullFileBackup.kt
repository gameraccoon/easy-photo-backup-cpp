package com.unnamed.easyphotobackup

import java.lang.AutoCloseable

class TestFullFileBackup(path: String) : AutoCloseable {
    private var nativeHandle: Long = create(path)

    private external fun create(localStorageDirectory: String): Long
    private external fun destroy(handle: Long)
    private external fun startDiscoveryNative(handle: Long)
    private external fun getDiscoveryResultsNative(handle: Long): Array<String>
    private external fun stopDiscoveryNative(handle: Long)
    private external fun requestServerNameNative(handle: Long, address: String) : String?
    // ToDo: this is a function that only exists for early testing, it should be removed asap
    private external fun pairAndApproveServerNative(handle: Long, address: String, serverName: String) : String?
    private external fun sendFilesNative(handle: Long, address: String, serverName: String, folderPath: String) : String?
    private external fun removeServerNative(handle: Long, serverName: String) : String?
    private external fun isServerPaired(handle: Long, serverName: String) : Boolean

    override fun close() {
        if (nativeHandle != 0L) {
            destroy(nativeHandle)
            nativeHandle = 0
        }
    }

    fun startDiscovery() {
        check(nativeHandle != 0L)
        startDiscoveryNative(nativeHandle)
    }

    fun getDiscoveryResults(): Array<String> {
        check(nativeHandle != 0L)
        return getDiscoveryResultsNative(nativeHandle)
    }

    fun stopDiscovery() {
        check(nativeHandle != 0L)
        stopDiscoveryNative(nativeHandle)
    }

    fun requestServerName(address: String): String? {
        check(nativeHandle != 0L)
        return requestServerNameNative(nativeHandle, address)
    }

    // ToDo: this is a function that only exists for early testing, it should be removed asap
    fun pairAndApproveServer(address: String, serverName: String) : String? {
        check(nativeHandle != 0L)
        return pairAndApproveServerNative(nativeHandle, address, serverName)
    }

    fun sendFiles(address: String, serverName: String, folderPath: String) : String? {
        check(nativeHandle != 0L)
        return sendFilesNative(nativeHandle, address, serverName, folderPath)
    }

    fun removeServer(serverName: String) : String? {
        check(nativeHandle != 0L)
        return removeServerNative(nativeHandle, serverName)
    }

    fun isServerPaired(serverName: String) : Boolean {
        check(nativeHandle != 0L)
        return isServerPaired(nativeHandle, serverName)
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}
