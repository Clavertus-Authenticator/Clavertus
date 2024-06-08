package ch.bfh.clavertus.authenticator.utils

import android.util.Log
import androidx.annotation.OptIn
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage

// Credits: https://developers.google.com/ml-kit/vision/barcode-scanning/android
typealias FidoQRListener = (qrString: String) -> Unit

class QrImageAnalyzer(listener: FidoQRListener? = null) : ImageAnalysis.Analyzer {

    private val listeners = ArrayList<FidoQRListener>().apply { listener?.let { add(it) } }

    @OptIn(ExperimentalGetImage::class)
    override fun analyze(imageProxy: ImageProxy) {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(
                Barcode.FORMAT_QR_CODE
            )
            .build()
        val mediaImage = imageProxy.image
        if (mediaImage != null) {
            val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
            BarcodeScanning.getClient(options).process(image)
                .addOnSuccessListener { barcodes ->
                    // Task completed successfully
                    for (barcode in barcodes) {
                        val rawValue = barcode.rawValue
                        val valueType = barcode.valueType
                        if (rawValue != null) {
                            if (valueType == Barcode.TYPE_TEXT && rawValue.startsWith("FIDO:/")) {
                                // Found a FIDO-TAG
                                listeners.forEach { it(rawValue.substringAfter("FIDO:/")) }
                            }
                        }
                    }
                }
                .addOnFailureListener {
                    // Task failed with an exception
                    Log.e(TAG, "QR code analysis failed!")
                }
                .addOnCompleteListener {
                    // release resources
                    imageProxy.close()
                }
        }
    }

    companion object {
        private val TAG = QrImageAnalyzer::class.java.simpleName
    }
}
