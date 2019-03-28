package com.bitcoin.securepreferences

private val hexArray = "0123456789ABCDEF".toCharArray()

fun ByteArray.toHexString(): String {
    val hexChars = CharArray(this.size * 2)
    for (j in this.indices) {
        val v: UByte = this[j].toUByte()
        hexChars[j * 2] = hexArray[v.toInt().ushr(4)]
        hexChars[j * 2 + 1] = hexArray[v.and(0x0F.toUByte()).toInt()]
    }
    return String(hexChars)
}