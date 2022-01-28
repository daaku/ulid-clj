package daaku.ulid;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public final class ULID {
    private static final int ULID_LENGTH = 26;
    private static final long MIN_TIME = 0x0L;
    private static final long MAX_TIME = 0x0000ffffffffffffL;

    private static final char[] C = new char[] {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q',
        'r', 's', 't', 'v', 'w', 'x', 'y', 'z'
    };

    private static final byte[] V = new byte[] {
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, -1, -1, -1, -1, -1, -1,
        -1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, -1, 0x12, 0x13, -1, 0x14, 0x15, -1,
        0x16, 0x17, 0x18, 0x19, 0x1a, -1, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, -1, -1, -1, -1, -1,
        -1, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, -1, 0x12, 0x13, -1, 0x14, 0x15, -1,
        0x16, 0x17, 0x18, 0x19, 0x1a, -1, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1
    };

    private static final ThreadLocal<Random> RANDOM = ThreadLocal.withInitial(() -> {
        try {
            return SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e.toString());
        }
    });

    /**
     * Generate ULID using a thread local SecureRandom instance.
     */
    public static String gen() {
        return gen(RANDOM.get());
    }

    /**
     * Generate ULID using provided Random source.
     */
    public static String gen(Random random) {
        byte[] entropy = new byte[10];
        random.nextBytes(entropy);
        return encode(System.currentTimeMillis(), entropy);
    }

    /**
     * Encode a timestamp and entropy to a ULID.
     */
    public static String encode(long time, byte[] entropy) {
        if (time < MIN_TIME || time > MAX_TIME || entropy == null || entropy.length < 10) {
            throw new IllegalArgumentException("invalid time or entropy");
        }

        char[] chars = new char[26];

        chars[0] = C[((byte) (time >>> 45)) & 0x1f];
        chars[1] = C[((byte) (time >>> 40)) & 0x1f];
        chars[2] = C[((byte) (time >>> 35)) & 0x1f];
        chars[3] = C[((byte) (time >>> 30)) & 0x1f];
        chars[4] = C[((byte) (time >>> 25)) & 0x1f];
        chars[5] = C[((byte) (time >>> 20)) & 0x1f];
        chars[6] = C[((byte) (time >>> 15)) & 0x1f];
        chars[7] = C[((byte) (time >>> 10)) & 0x1f];
        chars[8] = C[((byte) (time >>> 5)) & 0x1f];
        chars[9] = C[((byte) (time)) & 0x1f];

        chars[10] = C[(byte) ((entropy[0] & 0xff) >>> 3)];
        chars[11] = C[(byte) (((entropy[0] << 2) | ((entropy[1] & 0xff) >>> 6)) & 0x1f)];
        chars[12] = C[(byte) (((entropy[1] & 0xff) >>> 1) & 0x1f)];
        chars[13] = C[(byte) (((entropy[1] << 4) | ((entropy[2] & 0xff) >>> 4)) & 0x1f)];
        chars[14] = C[(byte) (((entropy[2] << 1) | ((entropy[3] & 0xff) >>> 7)) & 0x1f)];
        chars[15] = C[(byte) (((entropy[3] & 0xff) >>> 2) & 0x1f)];
        chars[16] = C[(byte) (((entropy[3] << 3) | ((entropy[4] & 0xff) >>> 5)) & 0x1f)];
        chars[17] = C[(byte) (entropy[4] & 0x1f)];
        chars[18] = C[(byte) ((entropy[5] & 0xff) >>> 3)];
        chars[19] = C[(byte) (((entropy[5] << 2) | ((entropy[6] & 0xff) >>> 6)) & 0x1f)];
        chars[20] = C[(byte) (((entropy[6] & 0xff) >>> 1) & 0x1f)];
        chars[21] = C[(byte) (((entropy[6] << 4) | ((entropy[7] & 0xff) >>> 4)) & 0x1f)];
        chars[22] = C[(byte) (((entropy[7] << 1) | ((entropy[8] & 0xff) >>> 7)) & 0x1f)];
        chars[23] = C[(byte) (((entropy[8] & 0xff) >>> 2) & 0x1f)];
        chars[24] = C[(byte) (((entropy[8] << 3) | ((entropy[9] & 0xff) >>> 5)) & 0x1f)];
        chars[25] = C[(byte) (entropy[9] & 0x1f)];

        return new String(chars);
    }

    /**
     * Check if a ULID string is valid.
     */
    public static boolean isValid(CharSequence ulid) {
        if (ulid == null || ulid.length() != ULID_LENGTH) {
            return false;
        }
        for (int i = 0; i < ULID_LENGTH; i++) {
            char c = ulid.charAt(i);
            if (c < 0 || c > V.length || V[c] == (byte) 0xff) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return the timestamp part from a ULID.
     */
    public static long timestamp(CharSequence ulid) {
        return (long) V[ulid.charAt(0)] << 45
            | (long) V[ulid.charAt(1)] << 40
            | (long) V[ulid.charAt(2)] << 35
            | (long) V[ulid.charAt(3)] << 30
            | (long) V[ulid.charAt(4)] << 25
            | (long) V[ulid.charAt(5)] << 20
            | (long) V[ulid.charAt(6)] << 15
            | (long) V[ulid.charAt(7)] << 10
            | (long) V[ulid.charAt(8)] << 5
            | (long) V[ulid.charAt(9)];
    }
}
