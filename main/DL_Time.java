package main;

import java.math.BigInteger;
import java.util.Random;

public class DL_Time {

    static int count = PublicParameters.COUNT;
    static int warmup = PublicParameters.WARMUP;
    private static long sl;
    private static long el;

    public static void DiscreteLogarithmTime() {
        Random rnd = new Random(System.currentTimeMillis());

        // =========================
        // ElGamal parameters
        // p = 1024 bit, x = 160 bit
        // =========================
        BigInteger elgamalMod = BigInteger.probablePrime(PublicParameters.ELGAMAL_MOD_BITS, rnd);

        ElGamalExpTime(elgamalMod, rnd);
        ElGamalModMulTime(elgamalMod, rnd);
        ElGamalModInverseTime(elgamalMod, rnd);

        // =========================
        // Paillier parameters
        // p = 512 bit, q = 512 bit
        // n = p*q ~ 1024 bit, modulus = n^2
        // =========================
        BigInteger p = BigInteger.probablePrime(PublicParameters.PAILLIER_PRIME_BITS, rnd);
        BigInteger q = BigInteger.probablePrime(PublicParameters.PAILLIER_PRIME_BITS, rnd);
        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);

        PaillierModPowTime(nSquared, rnd);
        PaillierModMulTime(nSquared, rnd);
        PaillierModInverseTime(n, rnd);
        PaillierLFunctionTime(nSquared, n, rnd);
    }

    // =========================
    // ElGamal: modPow with 160-bit exponent
    // =========================
    private static void ElGamalExpTime(BigInteger mod, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger base = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            if (base.equals(BigInteger.ZERO)) {
                base = BigInteger.TWO;
            }
            BigInteger exp = new BigInteger(PublicParameters.ELGAMAL_EXP_BITS, rnd);
            base.modPow(exp, mod);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger base = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            if (base.equals(BigInteger.ZERO)) {
                base = BigInteger.TWO;
            }

            BigInteger exp = new BigInteger(PublicParameters.ELGAMAL_EXP_BITS, rnd);

            sl = System.nanoTime();
            BigInteger result = base.modPow(exp, mod);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("ElGamal 幂运算平均时间：" + total / count + " ms");
    }

    // =========================
    // ElGamal: modular multiplication
    // =========================
    private static void ElGamalModMulTime(BigInteger mod, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger a = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            BigInteger b = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            a.multiply(b).mod(mod);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger a = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            BigInteger b = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);

            sl = System.nanoTime();
            BigInteger result = a.multiply(b).mod(mod);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("ElGamal 模乘运算平均时间：" + total / count + " ms");
    }

    // =========================
    // ElGamal: modular inverse
    // =========================
    private static void ElGamalModInverseTime(BigInteger mod, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger a;
            do {
                a = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            } while (a.equals(BigInteger.ZERO));
            a.modInverse(mod);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger a;
            do {
                a = new BigInteger(mod.bitLength() - 1, rnd).mod(mod);
            } while (a.equals(BigInteger.ZERO));

            sl = System.nanoTime();
            BigInteger result = a.modInverse(mod);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("ElGamal 模逆运算平均时间：" + total / count + " ms");
    }

    // =========================
    // Paillier: modPow under n^2
    // 统一按 1024-bit 指数规模测量
    // =========================
    private static void PaillierModPowTime(BigInteger nSquared, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger base = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            if (base.equals(BigInteger.ZERO)) {
                base = BigInteger.TWO;
            }
            BigInteger exp = new BigInteger(1024, rnd);
            base.modPow(exp, nSquared);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger base = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            if (base.equals(BigInteger.ZERO)) {
                base = BigInteger.TWO;
            }

            BigInteger exp = new BigInteger(1024, rnd);

            sl = System.nanoTime();
            BigInteger result = base.modPow(exp, nSquared);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("Paillier 模 n^2 下幂运算平均时间：" + total / count + " ms");
    }

    // =========================
    // Paillier: modular multiplication under n^2
    // =========================
    private static void PaillierModMulTime(BigInteger nSquared, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger a = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            BigInteger b = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            a.multiply(b).mod(nSquared);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger a = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            BigInteger b = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);

            sl = System.nanoTime();
            BigInteger result = a.multiply(b).mod(nSquared);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("Paillier 模 n^2 下模乘运算平均时间：" + total / count + " ms");
    }

    // =========================
    // Paillier: modular inverse under n
    // 更适合视为辅助运算或密钥相关运算
    // =========================
    private static void PaillierModInverseTime(BigInteger n, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength() - 1, rnd).mod(n);
            } while (a.equals(BigInteger.ZERO) || !a.gcd(n).equals(BigInteger.ONE));
            a.modInverse(n);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength() - 1, rnd).mod(n);
            } while (a.equals(BigInteger.ZERO) || !a.gcd(n).equals(BigInteger.ONE));

            sl = System.nanoTime();
            BigInteger result = a.modInverse(n);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("Paillier 模 n 下模逆运算平均时间：" + total / count + " ms");
    }

    // =========================
    // Paillier: L(u) = (u - 1) / n
    // 用于更合理估算解密中的线性变换开销
    // =========================
    private static void PaillierLFunctionTime(BigInteger nSquared, BigInteger n, Random rnd) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            BigInteger u = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            if (u.equals(BigInteger.ZERO)) {
                u = BigInteger.ONE;
            }
            u.subtract(BigInteger.ONE).divide(n);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            BigInteger u = new BigInteger(nSquared.bitLength() - 1, rnd).mod(nSquared);
            if (u.equals(BigInteger.ZERO)) {
                u = BigInteger.ONE;
            }

            sl = System.nanoTime();
            BigInteger l = u.subtract(BigInteger.ONE).divide(n);
            el = System.nanoTime();

            total += (el - sl);
        }

        total = total / 1000000.0;
        System.out.println("Paillier L 函数运算平均时间：" + total / count + " ms");
    }
}