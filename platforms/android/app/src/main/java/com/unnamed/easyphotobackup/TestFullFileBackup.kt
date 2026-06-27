package com.unnamed.easyphotobackup

import java.lang.AutoCloseable

class TestFullFileBackup(path: String) : AutoCloseable {
    private var nativeHandle: Long = create(path)

    private external fun create(localStorageDirectory: String): Long
    private external fun destroy(handle: Long)
    private external fun startDiscoveryNative(handle: Long)
    private external fun getDiscoveryResultsNative(handle: Long): LongArray
    private external fun stopDiscoveryNative(handle: Long)
    private external fun requestServerNameNative(handle: Long, serverInfoHandle: Long) : String?
    // ToDo: this is a function that only exists for early testing, it should be removed asap
    private external fun pairAndApproveServerNative(handle: Long, serverInfoHandle: Long) : String?
    private external fun sendFilesNative(handle: Long, serverInfoHandle: Long, folderPath: String, commonRoot: String) : String?
    private external fun removeServerNative(handle: Long, serverInfoHandle: Long) : String?
    private external fun isServerPaired(handle: Long, serverInfoHandle: Long) : Boolean

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

    fun getDiscoveryResults(): Array<TestServerInfo> {
        check(nativeHandle != 0L)

        return getDiscoveryResultsNative(nativeHandle)
            .map(::TestServerInfo)
            .toTypedArray()
    }

    fun stopDiscovery() {
        check(nativeHandle != 0L)
        stopDiscoveryNative(nativeHandle)
    }

    fun requestServerName(serverInfo: TestServerInfo): String? {
        check(nativeHandle != 0L)
        return requestServerNameNative(nativeHandle, serverInfo.nativeHandle)
    }

    // ToDo: this is a function that only exists for early testing, it should be removed asap
    fun pairAndApproveServer(serverInfo: TestServerInfo) : String? {
        check(nativeHandle != 0L)
        return pairAndApproveServerNative(nativeHandle, serverInfo.nativeHandle)
    }

    fun sendFiles(serverInfo: TestServerInfo, folderPath: String, commonRoot: String) : String? {
        check(nativeHandle != 0L)
        return sendFilesNative(nativeHandle, serverInfo.nativeHandle, folderPath, commonRoot)
    }

    fun removeServer(serverInfo: TestServerInfo) : String? {
        check(nativeHandle != 0L)
        return removeServerNative(nativeHandle, serverInfo.nativeHandle)
    }

    fun isServerPaired(serverInfo: TestServerInfo) : Boolean {
        check(nativeHandle != 0L)
        return isServerPaired(nativeHandle, serverInfo.nativeHandle)
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}

class TestServerInfo internal constructor(
    internal var nativeHandle: Long
) : AutoCloseable {

    private external fun destroy(handle: Long)

    override fun close() {
        if (nativeHandle != 0L) {
            destroy(nativeHandle)
            nativeHandle = 0
        }
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}
