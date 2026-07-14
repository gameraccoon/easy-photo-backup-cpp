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
    private external fun exchangePairingInformationWithServer(handle: Long, serverInfoHandle: Long) : Long
    private external fun approveServer(handle: Long, serverInfoHandle: Long, pendingServerBinding: Long) : String?
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

    fun exchangePairingInformationWithServer(serverInfo: TestServerInfo) : PendingServerBinding? {
        check(nativeHandle != 0L)
        val resultHandle = exchangePairingInformationWithServer(nativeHandle, serverInfo.nativeHandle)
        if (resultHandle == 0L)
        {
            return null
        }
        return PendingServerBinding(resultHandle)
    }

    fun approveServer(serverInfo: TestServerInfo, pendingServerBinding: PendingServerBinding) : String? {
        check(nativeHandle != 0L)
        return approveServer(nativeHandle, serverInfo.nativeHandle, pendingServerBinding.nativeHandle)
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

class PendingServerBinding internal constructor(
    internal var nativeHandle: Long
) : AutoCloseable {

    private external fun destroy(handle: Long)
    private external fun generateShortAuthentificationString(handle: Long) : String

    override fun close() {
        if (nativeHandle != 0L) {
            destroy(nativeHandle)
            nativeHandle = 0
        }
    }

    fun generateShortAuthentificationString(): String {
        check(nativeHandle != 0L)
        return generateShortAuthentificationString(nativeHandle)
    }

    companion object {
        init {
            System.loadLibrary("EasyPhotoBackupFfi")
        }
    }
}
