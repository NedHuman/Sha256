package dev.nedhuman;

import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        System.out.println(bytesToHex(new Sha256("hi".getBytes()).digest().get()));
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0'); // Add leading zero if needed
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}