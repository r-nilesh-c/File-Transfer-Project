package com.yourproject.utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class CustomByteCipher {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int KEY_INTERVAL = 256;

    private static int generateKey() {
        return secureRandom.nextInt(256);
    }

    private static void saveKeys(List<Integer> keys, String filePath) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int key : keys) {
            sb.append(key).append(System.lineSeparator());
        }
        Files.write(Paths.get(filePath), sb.toString().getBytes());
    }

    private static int loadKey(String filePath, int index) throws Exception {
        return Integer.parseInt(Files.readAllLines(Paths.get(filePath)).get(index));
    }

    private static int[][] generateKeyMatrix(int start, int end, int length, int randomKey) {
        return new int[][] {
            {start, end},
            {length, randomKey}
        };
    }

    private static int calculateDeterminant(int[][] matrix) {
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]);
    }

    public static byte[] encrypt(byte[] data) throws Exception {
        byte[] encryptedData = new byte[data.length];
        List<Integer> keys = new ArrayList<>();

        for (int i = 0; i < data.length; i++) {
            if (i % KEY_INTERVAL == 0) {
                int randomKey = generateKey();
                keys.add(randomKey);
            }
            int currentKey = keys.get(keys.size() - 1);
            int[][] keyMatrix = generateKeyMatrix(i, i - data.length, data.length, currentKey);
            int determinant = calculateDeterminant(keyMatrix);
            int encryptedByte = ((data[i] & 0xFF) + determinant) % 256;
            encryptedData[i] = (byte) (encryptedByte ^ currentKey);
        }

        saveKeys(keys, "encryption.keys");
        return encryptedData;
    }

    public static byte[] decrypt(byte[] encryptedData) throws Exception {
        byte[] decryptedData = new byte[encryptedData.length];
        List<Integer> keys = new ArrayList<>();

        for (int i = 0; i < encryptedData.length; i += KEY_INTERVAL) {
            keys.add(loadKey("encryption.keys", i / KEY_INTERVAL));
        }

        for (int i = 0; i < encryptedData.length; i++) {
            int currentKey = keys.get(i / KEY_INTERVAL);
            int[][] keyMatrix = generateKeyMatrix(i, i - encryptedData.length, encryptedData.length, currentKey);
            int determinant = calculateDeterminant(keyMatrix);
            int decryptedByte = ((encryptedData[i] & 0xFF) ^ currentKey);
            decryptedByte = (decryptedByte - determinant + 256) % 256;
            decryptedData[i] = (byte) decryptedByte;
        }
        return decryptedData;
    }
}
