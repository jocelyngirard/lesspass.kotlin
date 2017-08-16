package com.jclngrrd.lesspass.extension

fun Int.containBits(bits: Int): Boolean = bits and this == this
