package com.jclngrrd.lesspass

import com.jclngrrd.lesspass.extension.containBits
import java.math.BigInteger
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object LessPass {

    private val charactersSubsets = mapOf(
            PasswordFlags.LowerCase to "abcdefghijklmnopqrstuvwxyz",
            PasswordFlags.UpperCase to "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            PasswordFlags.Numeric to "0123456789",
            PasswordFlags.Symbols to "!\"#\$%&\\'()*+,-./:;<=>?@[\\\\]^_`{|}~"
    )

    enum class PasswordFlags(val flag: Int) {
        // Unitary flags
        LowerCase(0x01),
        UpperCase(0x02),
        Numeric(0x04),
        Symbols(0x08),
        // Combined flags
        Letters(LowerCase.flag or UpperCase.flag),
        AlphaNumeric(Letters.flag or Numeric.flag),
        All(AlphaNumeric.flag or Symbols.flag)
    }

    fun generatePassword(site: String, login: String, masterPassword: String, passwordProfile: PasswordProfile): String {
        return renderPassword(calcEntropy(site, login, masterPassword, passwordProfile), passwordProfile)
    }

    private fun calcEntropy(site: String, login: String, masterPassword: String, passwordProfile: PasswordProfile): ByteArray {
        val salt = site + login + Integer.toHexString(passwordProfile.counter)
        return PBKDF2WithHmacSHA256(masterPassword, salt, passwordProfile)
    }

    private fun PBKDF2WithHmacSHA256(masterPassword: String, salt: String, passwordProfile: PasswordProfile): ByteArray {
        return SecretKeyFactory.getInstance(passwordProfile.digest).let {
            val pbeKeySpec = PBEKeySpec(
                    masterPassword.toCharArray(),
                    salt.toByteArray(),
                    passwordProfile.iteration,
                    passwordProfile.keyLength * 8
            )
            it.generateSecret(pbeKeySpec).encoded
        }
    }

    private fun consumeEntropy(
            generatedPassword: StringBuffer,
            quotient: BigInteger,
            setOfCharacters: String,
            setLength: BigInteger,
            maxLength: Int
    ): Pair<String, Int> {
        return if (generatedPassword.length >= maxLength) {
            Pair(generatedPassword.toString(), quotient.toInt())
        } else {
            quotient.divideAndRemainder(setLength).let {
                generatedPassword.append(setOfCharacters[it.last().toInt()])
                consumeEntropy(generatedPassword, it.first(), setOfCharacters, setLength, maxLength)
            }
        }
    }


    private fun getOneCharPerRule(entropy: Int, flags: PasswordFlags): Pair<String, Int> {
        val oneCharPerRules = StringBuffer()
        LessPass.charactersSubsets.filter { it.key.flag.containBits(flags.flag) }.onEach {
            val (value, _) = consumeEntropy(
                    generatedPassword = StringBuffer(),
                    quotient = BigInteger.valueOf(entropy.toLong()),
                    setOfCharacters = it.value,
                    setLength = BigInteger.valueOf(it.value.length.toLong()),
                    maxLength = 1
            )
            oneCharPerRules.append(value)
        }
        return Pair(oneCharPerRules.toString(), entropy)
    }

    private fun insertStringPseudoRandomly(generatedPassword: String, entropy: Int, charactersToAdd: String): String {
        var password = generatedPassword
        var quotient = entropy
        for (index in 0 until charactersToAdd.length) {
            quotient /= generatedPassword.length
            val remainder = quotient % generatedPassword.length
            password = password.substring(0, remainder) + charactersToAdd[index] + password.substring(remainder)
        }
        return password
    }

    private fun renderPassword(entropy: ByteArray, passwordProfile: PasswordProfile): String {
        val listOfSets = charactersSubsets.filter { it.key.flag.containBits(passwordProfile.passwordFlags.flag) }.map { it.value }
        val setOfCharacters = listOfSets.joinToString("")
        val (password, passwordEntropy) = consumeEntropy(
                generatedPassword = StringBuffer(),
                quotient = BigInteger(entropy),
                setOfCharacters = setOfCharacters,
                setLength = BigInteger.valueOf(setOfCharacters.length.toLong()),
                maxLength = passwordProfile.length - listOfSets.size
        )
        val (charactersToAdd, characterEntropy) = getOneCharPerRule(passwordEntropy, passwordProfile.passwordFlags)
        return insertStringPseudoRandomly(password, characterEntropy, charactersToAdd)
    }
}