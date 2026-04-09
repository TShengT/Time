package main;

public class MyMain {
    public static void main(String[] args) {
        System.out.println("===== BigInteger 基础运算测试 =====");
        DL_Time.DiscreteLogarithmTime();

        System.out.println();
        System.out.println("===== JPBC 群运算测试 =====");
        GroupOperations.GroupOperations();
    }
}