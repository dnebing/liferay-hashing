# passwd-encryption-updator

So Liferay has support for changing your hashing algorithm any time by updating the 
`passwords.encryption.algorithm` property in portal-ext.properties.

The only problem is, well, that it only changes *if* your users actually change their password.

You can force this by setting all User entities password reset required flags and clear their
current passwords (to prevent reuse of the old algorithm), that will force
them to change their password when they log in, but boy, isn't this a bad UX?

I mean, when you are authenticating, Liferay knows to use the hash algorithm originally used to
determine if the password you provided hashes to the same value. If it is the same, then
authentication is successful.

What it should do next is check if the algorithm is the current default algorithm and, if
it is not, update the password to the new default hash since the password is there, valid
and also ready to rehash.

So this kind of lazy password rehashing taking place at authentication time is an ideal
and pain-free (at least for the user) method to update hashing schemes.

This module intends to provide that functionality, ensuring that hashes are updated after
successful login and while the password is still available to rehash.

NOTE: This is not going to be an _active_ rehash of all user passwords; the database
will contain their old password until they log into the platform, so you will still
have some hanging around unless you force everyone to reset their passwords.

Enjoy!