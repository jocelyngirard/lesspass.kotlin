package com.jclngrrd.lesspass

data class PasswordProfile(
        val version: Int = 2,
        val digest: String = "PBKDF2WithHmacSHA256",
        val iteration: Int = 100_000,
        val keyLength: Int = 32,

        val counter: Int = 1,
        val length: Int,
        val passwordFlags: LessPass.PasswordFlags
)