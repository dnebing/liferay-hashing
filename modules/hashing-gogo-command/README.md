# hashing-gogo-command

So this module only introduces a hash command set to use in the gogo shell.

The actual commands are:

| Command                          | Description                                        |
|----------------------------------|----------------------------------------------------|
| hash:none _password iterations_ | Does not hash, stores clear text password.         |
| hash:bcrypt _password rounds iterations_ | Uses the BCRYPT algorithm, rounds are commonly 10. |
| hash:md2 _password iterations_ | Uses the MD2 algorithm.                            |
| hash:md5 _password iterations_ | Uses the MD5 algorithm. |
| hash:pbkdf2 _password keySize rounds iterations_ | Uses the `PBKDF2WithHmacSHA1` algorithm, keySize is commonly 160, rounds one of 128,000, 720,000 or 1,300,000. |
| hash:sha _password iterations_ | Uses the `SHA` algorithm. |
