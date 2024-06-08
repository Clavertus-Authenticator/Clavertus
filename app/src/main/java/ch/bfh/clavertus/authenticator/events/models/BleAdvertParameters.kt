package ch.bfh.clavertus.authenticator.events.models

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings

data class BleAdvertParameters(
    val settings: AdvertiseSettings,
    val data: AdvertiseData,
    val callback: AdvertiseCallback
)
