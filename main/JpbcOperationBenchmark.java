import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Measures the following primitive-operation times:
 *
 * T_e  : modular exponentiation, a^e mod p
 * T_m  : modular multiplication, a*b mod p
 * T_h  : SHA-256 hash of a 32-byte message
 * T_i  : modular inverse, a^(-1) mod p
 * T_pa : one JPBC bilinear pairing, e(P, Q)
 * T_pl : Pollard's lambda algorithm for a bounded discrete logarithm
 *
 * Usage:
 *   java JpbcOperationBenchmark [pairing-parameter-file] [pollard-range-bits]
 *
 * Example:
 *   java JpbcOperationBenchmark a.properties 20
 *
 * With no arguments, the program generates Type A parameters with rBits=160
 * and qBits=512 before starting the timed measurements.
 */
public final class JpbcOperationBenchmark {

    private static final int MODULUS_BITS = 512;
    private static final int EXPONENT_BITS = 160;
    private static final int HASH_MESSAGE_BYTES = 32;

    private static final int NORMAL_WARMUP_ITERATIONS = 2_000;
    private static final int NORMAL_MEASURE_ITERATIONS = 5_000;
    private static final int HASH_MEASURE_ITERATIONS = 50_000;
    private static final int PAIRING_WARMUP_ITERATIONS = 100;
    private static final int PAIRING_MEASURE_ITERATIONS = 500;
    private static final int POLLARD_WARMUP_ITERATIONS = 1;
    private static final int POLLARD_MEASURE_ITERATIONS = 5;
    private static final int MEASUREMENT_ROUNDS = 7;

    /* Prevents the JIT compiler from removing apparently unused calculations. */
    private static volatile int blackHole;

    private JpbcOperationBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        Locale.setDefault(Locale.US);

        String pairingParameterFile = args.length >= 1 ? args[0] : null;
        int pollardRangeBits = args.length >= 2 ? Integer.parseInt(args[1]) : 20;
        if (pollardRangeBits < 8 || pollardRangeBits > 30) {
            throw new IllegalArgumentException(
                    "pollard-range-bits must be between 8 and 30 for this implementation.");
        }

        SecureRandom secureRandom = new SecureRandom();
        BigInteger modulus = BigInteger.probablePrime(MODULUS_BITS, secureRandom);
        BigInteger base = randomNonZeroBelow(modulus, secureRandom);
        BigInteger multiplier = randomNonZeroBelow(modulus, secureRandom);
        BigInteger exponent = new BigInteger(EXPONENT_BITS, secureRandom).setBit(EXPONENT_BITS - 1);
        byte[] hashMessage = new byte[HASH_MESSAGE_BYTES];
        secureRandom.nextBytes(hashMessage);

        Pairing pairing;
        String pairingDescription;
        if (pairingParameterFile == null) {
            TypeACurveGenerator curveGenerator = new TypeACurveGenerator(160, 512);
            PairingParameters pairingParameters = curveGenerator.generate();
            pairing = PairingFactory.getPairing(pairingParameters);
            pairingDescription = "generated Type A (rBits=160, qBits=512)";
        } else {
            pairing = PairingFactory.getPairing(pairingParameterFile);
            pairingDescription = pairingParameterFile;
        }
        Element pairingLeft = pairing.getG1().newRandomElement().getImmutable();
        Element pairingRight = pairing.getG2().newRandomElement().getImmutable();

        MessageDigest sha256 = newSha256();

        long pollardLower = 0L;
        long pollardUpper = (1L << pollardRangeBits) - 1L;
        Element pollardGenerator = pairing.getG1().newRandomElement().getImmutable();
        Element[] pollardTargets = new Element[POLLARD_MEASURE_ITERATIONS];
        long[] pollardSecrets = new long[POLLARD_MEASURE_ITERATIONS];
        Random testInputRandom = new Random(20260731L);
        for (int i = 0; i < POLLARD_MEASURE_ITERATIONS; i++) {
            long secret = nextLongBounded(testInputRandom, pollardUpper + 1L);
            pollardSecrets[i] = secret;
            pollardTargets[i] = pollardGenerator.duplicate()
                    .pow(BigInteger.valueOf(secret)).getImmutable();
        }

        Operation modularExponentiation = new Operation() {
            @Override
            public int run() {
                return base.modPow(exponent, modulus).hashCode();
            }
        };

        Operation modularMultiplication = new Operation() {
            @Override
            public int run() {
                return base.multiply(multiplier).mod(modulus).hashCode();
            }
        };

        Operation hashOperation = new Operation() {
            @Override
            public int run() {
                return sha256.digest(hashMessage)[0];
            }
        };

        Operation modularInverse = new Operation() {
            @Override
            public int run() {
                return base.modInverse(modulus).hashCode();
            }
        };

        Operation bilinearPairing = new Operation() {
            @Override
            public int run() {
                return pairing.pairing(pairingLeft, pairingRight).hashCode();
            }
        };

        Operation pollardLambda = new Operation() {
            private int targetIndex;

            @Override
            public int run() {
                int index = targetIndex++ % pollardTargets.length;
                long recovered = solveBoundedDiscreteLogWithPollardLambda(
                        pollardGenerator,
                        pollardTargets[index],
                        pollardLower,
                        pollardUpper);
                if (recovered != pollardSecrets[index]) {
                    throw new IllegalStateException(
                            "Pollard lambda returned " + recovered
                                    + ", expected " + pollardSecrets[index]);
                }
                return Long.valueOf(recovered).hashCode();
            }
        };

        System.out.println("JPBC primitive-operation benchmark");
        System.out.println("Pairing parameters : " + pairingDescription);
        System.out.println("Modulus size       : " + MODULUS_BITS + " bits");
        System.out.println("Exponent size      : " + EXPONENT_BITS + " bits");
        System.out.println("Hash               : SHA-256 over " + HASH_MESSAGE_BYTES + " bytes");
        System.out.println("Pollard interval   : [" + pollardLower + ", " + pollardUpper + "]");
        System.out.println("Reported value     : mean +/- sample standard deviation");
        System.out.println();

        warmUp(modularExponentiation, NORMAL_WARMUP_ITERATIONS);
        warmUp(modularMultiplication, NORMAL_WARMUP_ITERATIONS);
        warmUp(hashOperation, NORMAL_WARMUP_ITERATIONS);
        warmUp(modularInverse, NORMAL_WARMUP_ITERATIONS);
        warmUp(bilinearPairing, PAIRING_WARMUP_ITERATIONS);
        warmUp(pollardLambda, POLLARD_WARMUP_ITERATIONS);

        Stats te = measure(modularExponentiation, NORMAL_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);
        Stats tm = measure(modularMultiplication, NORMAL_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);
        Stats th = measure(hashOperation, HASH_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);
        Stats ti = measure(modularInverse, NORMAL_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);
        Stats tpa = measure(bilinearPairing, PAIRING_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);
        Stats tpl = measure(pollardLambda, POLLARD_MEASURE_ITERATIONS, MEASUREMENT_ROUNDS);

        System.out.printf("%-6s %-34s %15s %15s%n",
                "Symbol", "Operation", "mean (ms)", "std. dev. (ms)");
        System.out.println("------------------------------------------------------------------------");
        printResult("T_e", "modular exponentiation", te);
        printResult("T_m", "modular multiplication", tm);
        printResult("T_h", "SHA-256 hash", th);
        printResult("T_i", "modular inverse", ti);
        printResult("T_pa", "bilinear pairing", tpa);
        printResult("T_pl", "Pollard's lambda", tpl);

        System.out.println();
        System.out.println("Values in microseconds per operation:");
        printMicroseconds("T_e", te);
        printMicroseconds("T_m", tm);
        printMicroseconds("T_h", th);
        printMicroseconds("T_i", ti);
        printMicroseconds("T_pa", tpa);
        printMicroseconds("T_pl", tpl);

        if (blackHole == Integer.MIN_VALUE) {
            System.out.println("blackHole=" + blackHole);
        }
    }

    private static BigInteger randomNonZeroBelow(BigInteger modulus, SecureRandom random) {
        BigInteger value;
        do {
            value = new BigInteger(modulus.bitLength(), random);
        } while (value.signum() == 0 || value.compareTo(modulus) >= 0);
        return value;
    }

    private static MessageDigest newSha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void warmUp(Operation operation, int iterations) {
        int accumulator = 0;
        for (int i = 0; i < iterations; i++) {
            accumulator ^= operation.run();
        }
        blackHole ^= accumulator;
    }

    private static Stats measure(Operation operation, int iterations, int rounds) {
        double[] nanosecondsPerOperation = new double[rounds];
        for (int round = 0; round < rounds; round++) {
            int accumulator = 0;
            long start = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                accumulator ^= operation.run();
            }
            long elapsed = System.nanoTime() - start;
            blackHole ^= accumulator;
            nanosecondsPerOperation[round] = (double) elapsed / iterations;
        }
        return Stats.from(nanosecondsPerOperation);
    }

    private static void printResult(String symbol, String operation, Stats stats) {
        System.out.printf("%-6s %-34s %15.6f %15.6f%n",
                symbol, operation, stats.meanNanoseconds / 1_000_000.0,
                stats.standardDeviationNanoseconds / 1_000_000.0);
    }

    private static void printMicroseconds(String symbol, Stats stats) {
        System.out.printf("  %-4s = %.3f +/- %.3f us%n",
                symbol, stats.meanNanoseconds / 1_000.0,
                stats.standardDeviationNanoseconds / 1_000.0);
    }

    /**
     * Pollard's lambda, also called the kangaroo algorithm. It recovers x from
     * Y = G^x in a JPBC group, assuming lower <= x <= upper.
     *
     * This implementation stores tame-kangaroo points. Its memory use is
     * O(sqrt(upper-lower)) and is suitable for operation-time experiments.
     */
    private static long solveBoundedDiscreteLogWithPollardLambda(
            Element generator,
            Element target,
            long lower,
            long upper) {

        if (lower < 0L || upper < lower) {
            throw new IllegalArgumentException("Invalid Pollard interval");
        }

        long width = upper - lower;
        long squareRoot = ceilSquareRoot(width + 1L);
        int stepCount = Math.max(4, 64 - Long.numberOfLeadingZeros(squareRoot));
        long[] steps = new long[stepCount];
        Element[] groupSteps = new Element[stepCount];

        for (int attempt = 0; attempt < 4; attempt++) {
            for (int i = 0; i < stepCount; i++) {
                steps[i] = 1L << i;
                groupSteps[i] = generator.duplicate()
                        .pow(BigInteger.valueOf(steps[i])).getImmutable();
            }

            int tamePointCount = safeInt(12L * squareRoot + 512L);
            Map<ElementKey, Long> tamePoints =
                    new HashMap<ElementKey, Long>(tamePointCount * 2);

            Element tamePosition = generator.duplicate()
                    .pow(BigInteger.valueOf(upper)).getImmutable();
            long tameDistance = 0L;
            for (int i = 0; i < tamePointCount; i++) {
                ElementKey tameKey = new ElementKey(tamePosition);
                tamePoints.put(tameKey, tameDistance);
                int stepIndex = tameKey.partition(stepCount, attempt);
                tamePosition = tamePosition.duplicate()
                        .mul(groupSteps[stepIndex]).getImmutable();
                tameDistance += steps[stepIndex];
            }

            Element wildPosition = target;
            long wildDistance = 0L;
            long maximumWildDistance = width + tameDistance;

            while (wildDistance <= maximumWildDistance) {
                ElementKey wildKey = new ElementKey(wildPosition);
                Long matchingTameDistance = tamePoints.get(wildKey);
                if (matchingTameDistance != null) {
                    long candidate = upper + matchingTameDistance.longValue() - wildDistance;
                    if (candidate >= lower && candidate <= upper
                            && generator.duplicate().pow(BigInteger.valueOf(candidate))
                            .isEqual(target)) {
                        return candidate;
                    }
                }

                int stepIndex = wildKey.partition(stepCount, attempt);
                wildPosition = wildPosition.duplicate()
                        .mul(groupSteps[stepIndex]).getImmutable();
                wildDistance += steps[stepIndex];
            }
        }

        throw new IllegalStateException(
                "Pollard lambda did not find a logarithm in [" + lower + ", " + upper + "]");
    }

    private static long ceilSquareRoot(long value) {
        long root = (long) Math.sqrt((double) value);
        while (root * root < value) {
            root++;
        }
        while (root > 0L && (root - 1L) * (root - 1L) >= value) {
            root--;
        }
        return root;
    }

    private static int safeInt(long value) {
        if (value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Pollard interval is too large");
        }
        return (int) value;
    }

    private static long nextLongBounded(Random random, long bound) {
        if (bound <= 0L) {
            throw new IllegalArgumentException("bound must be positive");
        }
        long bits;
        long value;
        do {
            bits = random.nextLong() & Long.MAX_VALUE;
            value = bits % bound;
        } while (bits - value + (bound - 1L) < 0L);
        return value;
    }

    private interface Operation {
        int run();
    }

    private static final class ElementKey {
        private final byte[] encodedElement;
        private final int hashCode;

        private ElementKey(Element element) {
            this.encodedElement = element.toBytes();
            this.hashCode = Arrays.hashCode(encodedElement);
        }

        private int partition(int stepCount, int salt) {
            return Math.floorMod(hashCode + salt, stepCount);
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof ElementKey)) {
                return false;
            }
            ElementKey that = (ElementKey) other;
            return Arrays.equals(this.encodedElement, that.encodedElement);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
    }

    private static final class Stats {
        private final double meanNanoseconds;
        private final double standardDeviationNanoseconds;

        private Stats(double meanNanoseconds, double standardDeviationNanoseconds) {
            this.meanNanoseconds = meanNanoseconds;
            this.standardDeviationNanoseconds = standardDeviationNanoseconds;
        }

        private static Stats from(double[] samples) {
            double sum = 0.0;
            for (double sample : samples) {
                sum += sample;
            }
            double mean = sum / samples.length;

            double squaredDifferenceSum = 0.0;
            for (double sample : samples) {
                double difference = sample - mean;
                squaredDifferenceSum += difference * difference;
            }
            double standardDeviation = samples.length > 1
                    ? Math.sqrt(squaredDifferenceSum / (samples.length - 1))
                    : 0.0;
            return new Stats(mean, standardDeviation);
        }
    }
}