# bouncycastle-pbkdf2-passwd-encryptor

So this project actually has 3 primary components, but 4 classes.

The first class, the `BaseBouncyCastlePBKDF2PasswordEncryptor` is a base class that implements
everything, but it is an abstract class, not a component.

`BouncyCastlePBKDF2PasswordEncryptor` and `BouncyCastleReplacementPBKDF2PasswordEncryptor` both
extend the base class, they are both components, but they export different properties.

`BouncyCastlePBKDF2PasswordEncryptor` uses the type `BCPBKDF2WithHmacSHA1` so it is a completely
independent password encryptor. You could set your portal-ext.properties as:

```properties
# Leverage the Bouncy Castle fast implementation
passwords.encryption.algorithm=BCPBKDF2WithHmacSHA1/160/128000
```

`BouncyCastleReplacementPBKDF2PasswordEncryptor` uses Liferay's type, `PBKDF2`, so it is basically
a replacement for Liferay's `PBKDF2PasswordEncryptor`. You'll likely need to blocklist the
`com.liferay.portal.security.password.encryptor.internal.PBKDF2PasswordEncryptor` class
so Liferay doesn't use its own vs this override.

Finally, during testing, I found that Liferay's `CompositePasswordEncryptor` is the class that
looks up the right `PasswordEncryptor` based on the registered type, but it can't handle
parameters so my property defined above wouldn't match the Bouncy Castle encryptor since
the type property did not include any arguments (and it shouldn't, those are parameters).

So I copied Liferay's `CompositePasswordEncryptor` and made a slight change and gave my
implementation a higher service ranking. You should still blocklist the
`com.liferay.portal.security.password.encryptor.CompositePasswordEncryptor` to prevent
Liferay from binding to its own version.

So, to summarize... You can either:

1. Use `BCPBKDF2WithHmacSHA1` as your encryptor, but you'll also need the `CompositePasswordEncryptor`.
2. Use the `BouncyCastleReplacementPBKDF2PasswordEncryptor` to override Liferay's implementation.

Either way you're going to need to blocklist the appropriate Liferay component as documented above.

You could make it easy on yourself and just blocklist both of Liferay's components and run with
all of these components if you wanted, that way you'd be covered on all fronts.
