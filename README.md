# lesspass.kotlin
Simple LessPass implementation in Kotlin

## Usage
```kotlin
    val password = LessPass.generatePassword(
            site = "www.example.com",
            login = "john.doe",
            masterPassword = "this is my passphrase",
            passwordProfile = PasswordProfile(
                    counter = 1,
                    length = 16,
                    passwordFlags = LessPass.PasswordFlags.All
            )
    )
    println(password)
```
```
PArBj5ErXw'`-RPv
```