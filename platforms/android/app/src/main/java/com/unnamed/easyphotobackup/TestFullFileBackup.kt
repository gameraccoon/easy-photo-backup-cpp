package com.unnamed.easyphotobackup

import java.lang.AutoCloseable

class TestFullFileBackup : AutoCloseable {
    private var nativeHandle: Long = create()

    private external fun create(): Long
    private external fun destroy(handle: Long)
    private external fun startDiscoveryNative(handle: Long)
    private external fun getDiscoveryResultsNative(handle: Long)
    private external fun stopDiscoveryNative(handle: Long)
    private external fun requestServerNameNative(handle: Long, ip: String, port: Int) : String
    // ToDo: this is a function that only exists for early testing, it should be removed asap
    private external fun pairAndApproveServerNative(handle: Long)
    private external fun sendFilesNative(handle: Long)

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

    fun getDiscoveryResults() {
        check(nativeHandle != 0L)
        getDiscoveryResultsNative(nativeHandle)
    }

    fun stopDiscovery() {
        check(nativeHandle != 0L)
        stopDiscoveryNative(nativeHandle)
    }

    fun requestServerName(ip: String, port: Int) : String {
        check(nativeHandle != 0L)
        return requestServerNameNative(nativeHandle, ip, port)
    }

    // ToDo: this is a function that only exists for early testing, it should be removed asap
    fun pairAndApproveServer() {
        check(nativeHandle != 0L)
        pairAndApproveServerNative(nativeHandle)
    }

    fun sendFiles() {
        check(nativeHandle != 0L)
        sendFilesNative(nativeHandle)
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}
