package main;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class GroupOperations {

    private static int count = PublicParameters.COUNT;
    private static int warmup = PublicParameters.WARMUP;
    private static int LIMIT = PublicParameters.LIMIT;
    private static long sl;
    private static long el;

    static int rBits = PublicParameters.R_BITS;
    static int qBits = PublicParameters.Q_BITS;
    static TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
    static PairingParameters typeAParams = pg.generate();
    static Pairing pairing = PairingFactory.getPairing(typeAParams);

    public static void  GroupOperations() {
        G1MulTime(pairing);
        G1PowTime(pairing);
        G2PowTime(pairing);
        GTPairingTime(pairing);
        GTMulTime(pairing);
        hashTimes();
        Pol_time(pairing);

        // 如后续论文需要更细分的群运算，可打开下面这些
        // G1MulZrTime(pairing);
        // G1AddTime(pairing);
        // GTAddTime(pairing);
        // GTPowTime(pairing);

    }

    private static void hashTimes() {
        try {
            Hash2G1Time(pairing);
            Hash2ZrTime(pairing);
            GeneralHashTime();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    /**
     * 构造更贴近论文设定的消息输入：
     * 时间戳 64 bit + 身份标识 32 bit + 区域标识码 32 bit
     */
    private static byte[] buildMessageBytes(int i) {
        long timestamp = System.currentTimeMillis() + i; // 64 bit
        int identity = i;                               // 32 bit
        int regionCode = i + 1000;                      // 32 bit

        ByteBuffer buffer = ByteBuffer.allocate(8 + 4 + 4);
        buffer.putLong(timestamp);
        buffer.putInt(identity);
        buffer.putInt(regionCode);
        return buffer.array();
    }

    private static void GeneralHashTime() throws NoSuchAlgorithmException {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            byte[] msg = buildMessageBytes(i);
            Utilities.string2hash(new String(msg));
        }

        double total = 0;
        for (int i = 0; i < count; i++) {
            byte[] msg = buildMessageBytes(i);

            sl = System.nanoTime();
            String resultString = Utilities.string2hash(new String(msg));
            el = System.nanoTime();

            total += (el - sl);
        }
        total = total / 1000000.0;
        System.out.println("SHA-256 哈希平均时间：" + total / count + " ms");
    }

    private static void Hash2ZrTime(Pairing pairing) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            byte[] msg = buildMessageBytes(i);
            byte[] digest = Utilities.string2bytes(new String(msg));
            pairing.getZr().newElement().setFromHash(digest, 0, digest.length);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            byte[] msg = buildMessageBytes(i);
            total += Hash2ZrTime(pairing, msg);
        }
        total = total / 1000000.0;
        System.out.println("哈希到 Zr 平均时间：" + total / count + " ms");
    }

    private static void Hash2G1Time(Pairing pairing) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            byte[] msg = buildMessageBytes(i);
            byte[] digest = Utilities.string2bytes(new String(msg));
            pairing.getG1().newElement().setFromHash(digest, 0, digest.length);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            byte[] msg = buildMessageBytes(i);
            total += Hash2G1Time(pairing, msg);
        }
        total = total / 1000000.0;
        System.out.println("BLS 哈希到 G1 平均时间：" + total / count + " ms");
    }

    private static void G1MulTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG1MulTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG1MulTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("G1 群乘运算平均时间：" + total / count + " ms");
    }

    private static long calculateG1MulTime(Pairing pairing) {
        Element G_1 = pairing.getG1().newRandomElement().getImmutable();
        Element G_1_p = pairing.getG1().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_1_m_G_1 = G_1.mul(G_1_p);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void G1MulZrTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG1MulZrTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG1MulZrTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("G1 群标量乘平均时间：" + total / count + " ms");
    }

    private static long calculateG1MulZrTime(Pairing pairing) {
        Element G_1 = pairing.getG1().newRandomElement().getImmutable();
        Element Zr = pairing.getZr().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_1_m_G_1 = G_1.mulZn(Zr);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void G1PowTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG1PowTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG1PowTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("BLS G1 群指数运算平均时间：" + total / count + " ms");
    }

    private static long calculateG1PowTime(Pairing pairing) {
        Element G_1 = pairing.getG1().newRandomElement().getImmutable();
        Element Z = pairing.getZr().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_1_Pow_Zn = G_1.powZn(Z);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void G1AddTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG1AddTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG1AddTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("G1 群加法平均时间：" + total / count + " ms");
    }

    private static long calculateG1AddTime(Pairing pairing) {
        Element G_1 = pairing.getG1().newRandomElement().getImmutable();
        Element G_1_Add = pairing.getG1().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_1_Add_G_1 = G_1.add(G_1_Add);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void G2MulTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG2MulTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG2MulTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("G2 群乘运算平均时间：" + total / count + " ms");
    }

    private static long calculateG2MulTime(Pairing pairing) {
        Element G_2 = pairing.getG2().newRandomElement().getImmutable();
        Element G_2_p = pairing.getG2().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_2_m_G_2 = G_2.mul(G_2_p);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void G2PowTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateG2PowTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateG2PowTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("G2 群指数运算平均时间：" + total / count + " ms");
    }

    private static long calculateG2PowTime(Pairing pairing) {
        Element G_2 = pairing.getG2().newRandomElement().getImmutable();
        Element Z = pairing.getZr().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_2_Pow_Zn = G_2.powZn(Z);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void GTMulTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateGTMulTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateGTMulTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("配对乘法/GT 群乘运算平均时间：" + total / count + " ms");
    }

    private static long calculateGTMulTime(Pairing pairing) {
        Element G_T = pairing.getGT().newRandomElement().getImmutable();
        Element G_T_p = pairing.getGT().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_T_m_G_T = G_T.mul(G_T_p);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void GTAddTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateGTAddTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateGTAddTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("GT 群加法平均时间：" + total / count + " ms");
    }

    private static long calculateGTAddTime(Pairing pairing) {
        Element G_T = pairing.getGT().newRandomElement().getImmutable();
        Element G_T_p = pairing.getGT().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_T_m_G_T = G_T.add(G_T_p);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void GTPowTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculateGTPowTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculateGTPowTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("GT 群指数运算平均时间：" + total / count + " ms");
    }

    private static long calculateGTPowTime(Pairing pairing) {
        Element G_T = pairing.getGT().newRandomElement().getImmutable();
        Element Z = pairing.getZr().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_T_Pow_Zn = G_T.powZn(Z);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void GTPairingTime(Pairing pairing) {
        // warm-up
        for (int i = 0; i < warmup; i++) {
            calculatepairingTime(pairing);
        }

        double total = 0;

        for (int i = 0; i < count; i++) {
            total += calculatepairingTime(pairing);
        }
        total = total / 1000000.0;
        System.out.println("双线性配对运算平均时间：" + total / count + " ms");
    }

    private static long calculatepairingTime(Pairing pairing) {
        Element G_1 = pairing.getG1().newRandomElement().getImmutable();
        Element G_2 = pairing.getG2().newRandomElement().getImmutable();

        sl = System.nanoTime();
        Element G_p_G = pairing.pairing(G_1, G_2);
        el = System.nanoTime();
        return (el - sl);
    }

    private static long Hash2ZrTime(Pairing pairing, byte[] msgBytes)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        sl = System.nanoTime();
        byte[] digest = Utilities.string2bytes(new String(msgBytes));
        Element hash_Z_p = pairing.getZr().newElement().setFromHash(digest, 0, digest.length);
        el = System.nanoTime();
        return (el - sl);
    }

    private static long Hash2G1Time(Pairing pairing, byte[] msgBytes)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        sl = System.nanoTime();
        byte[] digest = Utilities.string2bytes(new String(msgBytes));
        Element hash_Z_p = pairing.getG1().newElement().setFromHash(digest, 0, digest.length);
        el = System.nanoTime();
        return (el - sl);
    }

    private static void Pol_time(Pairing pairing) {
        Element generator = pairing.getG1().newRandomElement().getImmutable();
        int times = 0;
        double total = 0;

        for (int i = 0; i < count; i++) {
            long randomNum = (long) (Math.random() * LIMIT);
            Element num = generator.pow(java.math.BigInteger.valueOf(randomNum));

            sl = System.nanoTime();
            int result = Utilities.longKangaroo(generator, num);
            el = System.nanoTime();

            total += el - sl;

            if (result == randomNum) {
                times++;
            }
        }
        total = total / 1000000.0;
        System.out.println("Pollard Kangaroo 求离散对数平均时间：" + total / count + " ms");
        System.out.println("求解成功次数：" + times);
        System.out.println("测试总次数：" + count);
    }
}