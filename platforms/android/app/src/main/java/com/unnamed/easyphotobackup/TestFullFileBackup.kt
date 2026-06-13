package com.unnamed.easyphotobackup

import java.lang.AutoCloseable

class TestFullFileBackup : AutoCloseable {
    private var nativeHandle: Long = create()

    private external fun create(): Long
    private external fun destroy(handle: Long)
    private external fun startDiscoveryNative(handle: Long)
    private external fun getDiscoveryResultsNative(handle: Long): Array<String>
    private external fun stopDiscoveryNative(handle: Long)
    private external fun requestServerNameNative(handle: Long, address: String) : String
    // ToDo: this is a function that only exists for early testing, it should be removed asap
    private external fun pairAndApproveServerNative(handle: Long, address: String, serverName: String)
    private external fun sendFilesNative(handle: Long, address: String, serverName: String, folderPath: String)

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

    fun requestServerName(address: String): String {
        check(nativeHandle != 0L)
        return requestServerNameNative(nativeHandle, address)
    }

    // ToDo: this is a function that only exists for early testing, it should be removed asap
    fun pairAndApproveServer(address: String, serverName: String) {
        check(nativeHandle != 0L)
        pairAndApproveServerNative(nativeHandle, address, serverName)
    }

    fun sendFiles(address: String, serverName: String, folderPath: String) {
        check(nativeHandle != 0L)
        sendFilesNative(nativeHandle, address, serverName, folderPath)
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}
