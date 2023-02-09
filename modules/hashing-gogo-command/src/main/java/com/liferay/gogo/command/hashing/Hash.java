package com.liferay.gogo.command.hashing;

import com.liferay.osgi.service.tracker.collections.EagerServiceTrackerCustomizer;
import com.liferay.osgi.service.tracker.collections.map.ServiceTrackerMapFactory;
import com.liferay.portal.events.StartupHelperUtil;
import com.liferay.portal.kernel.exception.PwdEncryptorException;
import com.liferay.portal.kernel.module.framework.ModuleServiceLifecycle;
import com.liferay.portal.kernel.security.pwd.PasswordEncryptor;
import com.liferay.portal.kernel.security.pwd.PasswordEncryptorUtil;
import org.apache.commons.lang.time.DurationFormatUtils;
import org.apache.felix.service.command.Descriptor;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Map;

@Component(
        immediate = true,
        property = {
                "osgi.command.scope=hash",
                "osgi.command.function=bcrypt",
                "osgi.command.function=md2",
                "osgi.command.function=md5",
                "osgi.command.function=none",
                "osgi.command.function=pbkdf2",
                "osgi.command.function=simplepbkdf2",
                "osgi.command.function=sha",
                "osgi.command.function=sha256",
                "osgi.command.function=sha512",
                "osgi.command.function=ssha",
                "osgi.command.function=ufccrypt",
                "osgi.command.function=all",
                "osgi.command.function=bcpbkdf2",
                "osgi.command.function=simplebcpbkdf2",
                "osgi.command.function=verifyPbkdf2"
        }, service = Object.class
)
public class Hash {

    private static final Logger _log = LoggerFactory.getLogger(Hash.class);

    private BundleContext _bundleContext;
    @Activate
    protected void activate(BundleContext bundleContext, Map<String, Object> properties) {

        _log.info("Hash command is activating...");

        _bundleContext = bundleContext;
    }

    @Descriptor("Performs the bcrypt hash test, args password, hash rounds, iterations.")
    public void bcrypt(final String password, final String roundsStr, final String iterations) {
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 10;
        }

        final String algorithm = PasswordEncryptor.TYPE_BCRYPT + "/" + rounds;

        hash(algorithm, password, iterations);
    }

    @Descriptor("Performs the MD2 hash test, args password, iterations.")
    public void md2(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_MD2, password, iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void md5(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_MD5, password, iterations);
    }

    @Descriptor("Performs the none-hash test, args password, iterations.")
    public void none(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_NONE, password, iterations);
    }

    @Descriptor("Performs the PBKDF2 hash test, args password, key size, rounds, iterations.")
    public void pbkdf2(final String password, final String keySizeStr, final String roundsStr, final String iterations) {
        int keySize = Integer.parseInt(keySizeStr);
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 128000;
        }

        final String algorithm = PasswordEncryptor.TYPE_PBKDF2 + "WithHmacSHA1/" + keySize + "/" + rounds;

        hash(algorithm, password, iterations);
    }

    @Descriptor("Verifies that Liferay's PBKDF2 and BouncyCastle's PBKDF2 implementations create the same hash value.")
    public void verifyPbkdf2(String password) {

        try {
            String pbkdf2Hash = PasswordEncryptorUtil.encrypt(PasswordEncryptor.TYPE_PBKDF2 + "WithHmacSHA1/160/128000", password, (String) null);
            String bcHash = PasswordEncryptorUtil.encrypt("BCPBKDF2WithHmacSHA1/160/128000", password, pbkdf2Hash);
            boolean same = pbkdf2Hash.equals(bcHash);

            _log.info("Verifying the equality of Liferay's PBKDF2 hash and BouncyCastle's PBKDF2 hash:");

            _log.info("128,000 Match: " + same);
            _log.info("LR 128,000: " + pbkdf2Hash);
            _log.info("BC 128,000: " + bcHash);

            System.out.println("128,000 Match: " + same);
            System.out.println("LR 128,000: " + pbkdf2Hash);
            System.out.println("BC 128,000: " + bcHash);

            pbkdf2Hash = PasswordEncryptorUtil.encrypt(PasswordEncryptor.TYPE_PBKDF2 + "WithHmacSHA1/160/720000", password, (String) null);
            bcHash = PasswordEncryptorUtil.encrypt("BCPBKDF2WithHmacSHA1/160/720000", password, pbkdf2Hash);
            same = pbkdf2Hash.equals(bcHash);

            _log.info("128,000 Match: " + same);
            _log.info("LR 720,000: " + pbkdf2Hash);
            _log.info("BC 720,000: " + bcHash);

            System.out.println("128,000 Match: " + same);
            System.out.println("LR 720,000: " + pbkdf2Hash);
            System.out.println("BC 720,000: " + bcHash);

            pbkdf2Hash = PasswordEncryptorUtil.encrypt(PasswordEncryptor.TYPE_PBKDF2 + "WithHmacSHA1/160/1300000", password, (String) null);
            bcHash = PasswordEncryptorUtil.encrypt("BCPBKDF2WithHmacSHA1/160/1300000", password, pbkdf2Hash);
            same = pbkdf2Hash.equals(bcHash);

            _log.info("128,000 Match: " + same);
            _log.info("LR 1,300,000: " + pbkdf2Hash);
            _log.info("BC 1,300,000: " + bcHash);

            System.out.println("128,000 Match: " + same);
            System.out.println("LR 1,300,000: " + pbkdf2Hash);
            System.out.println("BC 1,300,000: " + bcHash);
        } catch (PwdEncryptorException e) {
            _log.error("Error calculating hashes: {}", e.getMessage(), e);
            System.err.println("Error calculating hashes: " + e.getMessage());
        }
    }

    @Descriptor("Performs all the PBKDF2 hash tests, args password, iterations.")
    public void simplepbkdf2(final String password, final String iterations) {
        pbkdf2(password, "160", "128000", iterations);
        pbkdf2(password, "160", "720000", iterations);
        pbkdf2(password, "160", "1300000", iterations);
    }

    @Descriptor("Performs the BouncyCastle PBKDF2 hash test, args password, key size, rounds, iterations.")
    public void bcpbkdf2(final String password, final String keySizeStr, final String roundsStr, final String iterations) {
        int keySize = Integer.parseInt(keySizeStr);
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 128000;
        }

        final String algorithm = "BCPBKDF2WithHmacSHA1/" + keySize + "/" + rounds;

        hash(algorithm, password, iterations);
    }

    @Descriptor("Performs all the Bouncy Castle PBKDF2 hash tests, args password, iterations.")
    public void simplebcpbkdf2(final String password, final String iterations) {
        bcpbkdf2(password, "160", "128000", iterations);
        bcpbkdf2(password, "160", "720000", iterations);
        bcpbkdf2(password, "160", "1300000", iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void sha(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_SHA, password, iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void sha256(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_SHA_256, password, iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void sha384(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_SHA_384, password, iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void ssha(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_SSHA, password, iterations);
    }

    @Descriptor("Performs the MD5 hash test, args password, iterations.")
    public void ufccrypt(final String password, final String iterations) {
        hash(PasswordEncryptor.TYPE_UFC_CRYPT, password, iterations);
    }

    @Descriptor("Performs the all of the hash tests, args password, iterations.")
    public void all(final String password, final String iterations) {
        none(password, iterations);
        bcrypt(password, "10", iterations);
        md2(password, iterations);
        md5(password, iterations);
        simplepbkdf2(password, iterations);
        simplebcpbkdf2(password, iterations);
        sha(password, iterations);
        sha256(password, iterations);
        sha384(password, iterations);
        ssha(password, iterations);
        ufccrypt(password, iterations);
    }

    /**
     * hash: Internal method that uses the given algorithm to time the hashing of the given password for the given number of iterations.
     * @param algorithm Algorithm to use.
     * @param password Password to hash.
     * @param iterationsStr Number of iterations to repeat hashing (for performing averaging).
     */
    protected void hash(final String algorithm, final String password, final String iterationsStr) {
        long duration = 0;

        int iterations = Integer.parseInt(iterationsStr);

        if (iterations < 1) {
            iterations = 1;
        }

        long start, end;
        String hash = null;

        for (int idx = 0; idx < iterations; idx++) {
            try {
                start = System.currentTimeMillis();
                hash = PasswordEncryptorUtil.encrypt(algorithm, password, (String) null);
                end = System.currentTimeMillis();

                duration += (end - start);
            } catch (PwdEncryptorException e) {
                _log.error("Error computing hash: " + e.getMessage());
                return;
            }
        }

        System.out.println(algorithm + ":");
        System.out.println("  Hashed Password: " + hash);
        System.out.println("  Time for " + iterations + " loops: " + duration + " ms (" + DurationFormatUtils.formatDurationWords(duration, true, true) + ")");
        System.out.println("  Average time: " + (duration / iterations) + " ms");

        _log.info(algorithm + ":");
        _log.info("  Hashed Password: {}", hash);
        _log.info("  Time for {} loops: {} ms ({})", iterations, duration, DurationFormatUtils.formatDurationWords(duration, true, true));
        _log.info("  Average time: {} ms", (duration / iterations));
    }

    @Reference(target = ModuleServiceLifecycle.PORTAL_INITIALIZED)
    private ModuleServiceLifecycle _moduleServiceLifecycle;
}
