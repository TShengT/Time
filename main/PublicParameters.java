package main;

public class PublicParameters {

    // 计时轮数
    public static final int COUNT = 1;

    // 预热轮数，避免 JVM 刚启动时影响结果
    public static final int WARMUP = 200;

    // Pollard Kangaroo 小范围实验参数
    public static int LIMIT = 100000;
    public static int LEAPES = 316;   // = square root of LIMIT

    // =========================
    // ElGamal 参数
    // 模数 1024 bit，指数 160 bit
    // =========================
    public static final int ELGAMAL_MOD_BITS = 1024;
    public static final int ELGAMAL_EXP_BITS = 160;

    // =========================
    // Paillier 参数
    // p 和 q 各 512 bit，因此 n 约 1024 bit
    // =========================
    public static final int PAILLIER_PRIME_BITS = 512;

    // =========================
    // JPBC Type A pairing 参数
    // q = 512 bit, r = 160 bit
    // =========================
    public static final int Q_BITS = 512;
    public static final int R_BITS = 160;

    // =========================
    // 消息字段长度（用于构造哈希输入）
    // 时间戳 64 bit，身份标识 32 bit，区域标识码 32 bit
    // =========================
    public static final int TIMESTAMP_BITS = 64;
    public static final int ID_BITS = 32;
    public static final int REGION_BITS = 32;

    // 哈希算法
    public static final String HASH_ALGORITHM = "SHA-256";
}