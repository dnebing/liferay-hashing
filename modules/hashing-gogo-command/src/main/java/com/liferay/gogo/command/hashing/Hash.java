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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

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

    @Descriptor("Performs the bcrypt hash test, args password, hash rounds, hashes, threads.")
    public void bcrypt(final String password, final String roundsStr, final String hashes, final String threads) {
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 10;
        }

        final String algorithm = PasswordEncryptor.TYPE_BCRYPT + "/" + rounds;

        hash(algorithm, password, hashes, threads);
    }

    @Descriptor("Performs the MD2 hash test, args password, hashes, threads.")
    public void md2(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_MD2, password, hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void md5(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_MD5, password, hashes, threads);
    }

    @Descriptor("Performs the none-hash test, args password, hashes, threads.")
    public void none(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_NONE, password, hashes, threads);
    }

    @Descriptor("Performs the PBKDF2 hash test, args password, key size, rounds, hashes, threads.")
    public void pbkdf2(final String password, final String keySizeStr, final String roundsStr, final String hashes, final String threads) {
        int keySize = Integer.parseInt(keySizeStr);
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 128000;
        }

        final String algorithm = PasswordEncryptor.TYPE_PBKDF2 + "WithHmacSHA1/" + keySize + "/" + rounds;

        hash(algorithm, password, hashes, threads);
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

    @Descriptor("Performs all the PBKDF2 hash tests, args password, hashes, threads.")
    public void simplepbkdf2(final String password, final String hashes, final String threads) {
        pbkdf2(password, "160", "128000", hashes, threads);
        pbkdf2(password, "160", "720000", hashes, threads);
        pbkdf2(password, "160", "1300000", hashes, threads);
    }

    @Descriptor("Performs the BouncyCastle PBKDF2 hash test, args password, key size, rounds, hashes, threads.")
    public void bcpbkdf2(final String password, final String keySizeStr, final String roundsStr, final String hashes, final String threads) {
        int keySize = Integer.parseInt(keySizeStr);
        int rounds = Integer.parseInt(roundsStr);
        if (rounds < 1) {
            rounds = 128000;
        }

        final String algorithm = "BCPBKDF2WithHmacSHA1/" + keySize + "/" + rounds;

        hash(algorithm, password, hashes, threads);
    }

    @Descriptor("Performs all the Bouncy Castle PBKDF2 hash tests, args password, hashes, threads.")
    public void simplebcpbkdf2(final String password, final String hashes, final String threads) {
        bcpbkdf2(password, "160", "128000", hashes, threads);
        bcpbkdf2(password, "160", "720000", hashes, threads);
        bcpbkdf2(password, "160", "1300000", hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void sha(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_SHA, password, hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void sha256(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_SHA_256, password, hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void sha384(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_SHA_384, password, hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void ssha(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_SSHA, password, hashes, threads);
    }

    @Descriptor("Performs the MD5 hash test, args password, hashes, threads.")
    public void ufccrypt(final String password, final String hashes, final String threads) {
        hash(PasswordEncryptor.TYPE_UFC_CRYPT, password, hashes, threads);
    }

    @Descriptor("Performs the all of the hash tests, args password, hashes, threads.")
    public void all(final String password, final String hashes, final String threads) {
        none(password, hashes, threads);
        bcrypt(password, "10", hashes, threads);
        md2(password, hashes, threads);
        md5(password, hashes, threads);
        simplepbkdf2(password, hashes, threads);
        simplebcpbkdf2(password, hashes, threads);
        sha(password, hashes, threads);
        sha256(password, hashes, threads);
        sha384(password, hashes, threads);
        ssha(password, hashes, threads);
        ufccrypt(password, hashes, threads);
    }

    /**
     * hash: Internal method that uses the given algorithm to time the hashing of the given password for the given number of threads.
     * @param algorithm Algorithm to use.
     * @param password Password to hash.
     * @param hashesStr Number of hashes to complete
     * @param threadsStr Number of threads to repeat hashing (for performing averaging).
     */
    protected void hash(final String algorithm, final String password, final String hashesStr, final String threadsStr) {
        int numThreads = Integer.parseInt(threadsStr);

        if (numThreads < 1) {
            numThreads = 10;
        }

        int hashes = Integer.parseInt(hashesStr);

        if (hashes < 1) {
            hashes = 10 * numThreads;
        }

        String hash = null;
        try {
            hash = PasswordEncryptorUtil.encrypt(algorithm, password, (String) null);
        } catch (PwdEncryptorException e) {
            _log.error("Error computing hash: " + e.getMessage());
        }

        long startTime = System.currentTimeMillis();

        // create the thread pool to process the hashes.
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        // create a queue for all of the hash activity
        LinkedBlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>();

        // Add all the hash requests to the queue
        for (int i = 0; i < hashes; i++) {
            workQueue.add(() -> {
                try {
                    PasswordEncryptorUtil.encrypt(algorithm, password, (String) null);
                } catch (PwdEncryptorException e) {
                    _log.error("Error computing hash: " + e.getMessage(), e);
                }
            });
        }

        // Submit the hash requests to the executor pool
        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                while (true) {
                    Runnable workItem = workQueue.poll();
                    if (workItem == null) {
                        break; // No more work items in the queue
                    }
                    workItem.run();
                }
            });
        }

        // Wait for all threads to finish
        executor.shutdown();
        while (!executor.isTerminated()) {
            Thread.yield();
        }

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;

        String duration = "";

        if (totalTime > 999) {
            duration = " (" + DurationFormatUtils.formatDurationWords(totalTime, true, true) + ")";
        }

        long throughput = (hashes / (totalTime < 1 ? 1 : totalTime));
        long avg = totalTime / hashes;

        System.out.println(algorithm + ":");
        System.out.println("  Hashed Password: " + hash);
        System.out.println("  Time for " + hashes + " on " + numThreads + " threads: " + totalTime + " ms" + duration);
        if (throughput > 0) {
            System.out.println("  Throughput: " + throughput + " per ms");
        }
        if (avg > 0) {
            System.out.println("  Average: " + avg + " ms per hash");
        }
        System.out.flush();

        _log.info(algorithm + ":");
        _log.info("  Hashed Password: {}", hash);
        _log.info("  Time for {} hashes on {} threads: {} ms{}", hashes, numThreads, totalTime, duration);
        if (throughput > 0) {
            _log.info("  Throughput: {} per ms", throughput);
        }
        if (avg > 0) {
            _log.info("  Average: {} ms per hash", avg);
        }
    }

    @Reference(target = ModuleServiceLifecycle.PORTAL_INITIALIZED)
    private ModuleServiceLifecycle _moduleServiceLifecycle;

}
