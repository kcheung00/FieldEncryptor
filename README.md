# FieldEncryptor
Encrypt or decrypt field of a properties file


How to use:

To encrypt:
```
java FieldEncryptor -e db.password,db.username src/main/resources/config.properties
```

To decrypt:
```
java FieldEncryptor -d db.password,db.username src/main/resources/config.properties
```

The program marks encrypted fields with {enc} to avoid double encryption.

You can specify multiple fields separated by commas.

The program reads and writes directly to the specified properties file.

Uses a strong random 32-byte key (change as needed for your environment).
