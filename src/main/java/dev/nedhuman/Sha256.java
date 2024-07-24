package dev.nedhuman;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPairGenerator;
import java.util.Arrays;

/**
 * Sha256 implementation from scratch in java
 * @author NedHuman
 */
public class Sha256 {

    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    private static final int[] H = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private byte[] data;
    private Block[] blocks;

    /**
     * Initialise a Sha256 object
     * @param data the data to hash
     */
    public Sha256(byte[] data) {
        this.data = data;
    }

    /**
     * Digest the data. The new sha256 hash is now obtainable with {@link #get()}
     */
    public Sha256 digest() {
        pad();

        blocks = Block.organiseToBlocks(data);
        int[] h = new int[8];
        System.arraycopy(H, 0, h, 0, h.length);

        for(Block i : blocks) {
            int[] w = new int[64];
            System.arraycopy(i.words, 0, w, 0, 16);

            for(int t = 16; t < w.length; t++) {
                w[t] = smallSig1(w[t-2])+w[t-7]+smallSig0(w[t-15])+w[t-16];
            }

            int[] ah = new int[8];
            System.arraycopy(h, 0, ah, 0, ah.length);

            for(int t = 0; t < 64; t++) {
                int t1 = ah[7]+bigSig1(ah[4])+ch(ah[4], ah[5], ah[6])+K[t]+w[t];
                int t2 = bigSig0(ah[0])+maj(ah[0], ah[1], ah[2]);
                ah[7] = ah[6];
                ah[6] = ah[5];
                ah[5] = ah[4];
                ah[4] = ah[3]+t1;
                ah[3] = ah[2];
                ah[2] = ah[1];
                ah[1] = ah[0];
                ah[0] = t1+t2;
            }

            for(int l = 0; l < h.length; l++) {
                h[l] = h[l]+ah[l];
            }
        }

        ByteBuffer buffer = ByteBuffer.allocate(32);
        for(int i : h) {
            buffer.putInt(i);
        }
        buffer.flip();
        byte[] temp = new byte[32];
        buffer.get(temp);
        data = temp;
        return this;
    }

    /**
     * Returns the data stored in this Sha256 object
     * @return the data stored in this Sha256 object
     */
    public byte[] get() {
        return data;
    }


    private void pad() {
        int messageLenBits = data.length * 8;

        byte[] paddedMessage = Arrays.copyOf(data, data.length + 1);
        paddedMessage[data.length] = (byte) 0x80;

        int lengthMod512 = (messageLenBits + 8) % 512;
        int paddingLenBits = (lengthMod512 <= 448) ? (448 - lengthMod512) : (960 - lengthMod512);

        int paddingLenBytes = paddingLenBits / 8;

        paddedMessage = Arrays.copyOf(paddedMessage, paddedMessage.length + paddingLenBytes);

        byte[] lengthBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(messageLenBits).array();

        paddedMessage = Arrays.copyOf(paddedMessage, paddedMessage.length + lengthBytes.length);
        System.arraycopy(lengthBytes, 0, paddedMessage, paddedMessage.length - lengthBytes.length, lengthBytes.length);

        data = paddedMessage;
    }

    private static int smallSig0(int x) {
        return Integer.rotateRight(x, 7)
                ^ Integer.rotateRight(x, 18)
                ^ (x >>> 3);
    }

    private static int smallSig1(int x) {
        return Integer.rotateRight(x, 17)
                ^ Integer.rotateRight(x, 19)
                ^ (x >>> 10);
    }

    private static int ch(int x, int y, int z) {
        return (x & y) | ((~x) & z);
    }

    private static int maj(int x, int y, int z) {
        return (x & y) | (x & z) | (y & z);
    }

    private static int bigSig0(int x) {
        return Integer.rotateRight(x, 2)
                ^ Integer.rotateRight(x, 13)
                ^ Integer.rotateRight(x, 22);
    }

    private static int bigSig1(int x) {
        return Integer.rotateRight(x, 6)
                ^ Integer.rotateRight(x, 11)
                ^ Integer.rotateRight(x, 25);
    }

    private static class Block {

        private int[] words;

        private Block(ByteBuffer buffer) {
            words = new int[16];
            for(int i = 0; i < 16; i++) {
                words[i] = buffer.getInt();
            }
        }

        public static Block[] organiseToBlocks(byte[] data) {
            int blockAmount = data.length / 64;
            Block[] blocks = new Block[blockAmount];
            ByteBuffer buffer = ByteBuffer.allocate(data.length);
            buffer.put(data);
            buffer.flip();
            for(int i = 0; i < blockAmount; i++) {
                blocks[i] = new Block(buffer);
            }
            return blocks;
        }
    }


}
