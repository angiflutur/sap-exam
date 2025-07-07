package assignments;

import java.util.BitSet;

public class Assignment01 {
    public static int initRegisterInt(byte[] initialValues) {
        if (initialValues.length != 4) {
            System.out.println("Wrong initial value. 4 bytes needed");
            return 0;
        }
        int result = 0;
        for (int i = 3; i >= 0; i--) {
            result = result |
                    (((int) initialValues[3 - i] & 0xFF) << (i * 8));
        }
        return result;
    }

    public static BitSet initRegisterBitSet(byte[] initialValues) {
        if (initialValues.length != 4) {
            System.out.println("Wrong initial value. 4 bytes needed");
            return null;
        }
        BitSet bitSet = new BitSet(32);
        for (int i = 0; i < 4; i++) {
            for (int j = 7; j >= 0; j--) {
                if ((initialValues[i] & (1 << j)) != 0) {
                    bitSet.set(i * 8 + (7 - j));
                }
            }
        }
        return bitSet;
    }

    public static byte applyTapSequenceInt(int register) {
        byte result = 0;

        byte[] index = {31, 7, 5, 3, 2, 1, 0};
        for (int i = 0; i < index.length; i++) {
            byte bitValue = (byte) (((1 << index[i]) & register) >>> index[i]);
            result = (byte) (result ^ bitValue);
        }

        return result;
    }

    public static byte applyTapSequenceBitSet(BitSet register) {
        byte result = 0;

        int[] index = {31, 7, 5, 3, 2, 1, 0};
        for (int i : index) {
            byte bitValue = (byte) (register.get(i) ? 1 : 0);
            result = (byte) (result ^ bitValue);
        }

        return result;
    }

    public static byte getLeastSignificantBitInt(int register) {
        return (byte) (register & 1);
    }

    public static byte getLeastSignificantBitBitSet(BitSet register) {
        return (byte) (register.get(0) ? 1 : 0);
    }

    public static int shiftAndInsertTapBitInt(int register, byte tapBit) {
        register = register >>> 1;
        register = register | (tapBit << 31);
        return register;
    }

    public static BitSet shiftAndInsertTapBitBitSet(BitSet register, byte tapBit) {
        BitSet result = new BitSet(32);
        result.or(register.get(1, 32));
        result.set(31, tapBit != 0);

        return result;
    }

    public static void printBytes(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            System.out.printf("%02X ", bytes[i]);
        }
    }

    public static byte fullStepInt(int[] register) {
        byte tapBit = applyTapSequenceInt(register[0]);
        byte outputBit = getLeastSignificantBitInt(register[0]);
        register[0] = shiftAndInsertTapBitInt(register[0], tapBit);
        return outputBit;
    }

    public static byte fullStepBitSet(BitSet[] register) {
        byte tapBit = applyTapSequenceBitSet(register[0]);
        byte outputBit = getLeastSignificantBitBitSet(register[0]);
        register[0] = shiftAndInsertTapBitBitSet(register[0], tapBit);
        return outputBit;
    }

    public static byte[] generatePseudoBytesInt(int register, int numBytes) {
        byte[] outputBytes = new byte[numBytes];
        int[] registerArray = {register};
        for (int i = 0; i < numBytes; i++) {
            byte pseudoByte = 0;
            for (int j = 0; j < 8; j++) {
                byte outputBit = fullStepInt(registerArray);
                pseudoByte |= (outputBit << (7 - j));
            }
            outputBytes[i] = pseudoByte;
        }
        return outputBytes;
    }

    public static byte[] generatePseudoBytesBitSet(BitSet register, int numBytes) {
        byte[] outputBytes = new byte[numBytes];
        BitSet[] registerArray = {register};

        for (int i = 0; i < numBytes; i++) {
            byte pseudoByte = 0;
            for (int j = 0; j < 8; j++) {
                byte outputBit = fullStepBitSet(registerArray);
                pseudoByte |= (outputBit << (7 - j));
            }
            outputBytes[i] = pseudoByte;
        }

        return outputBytes;
    }

    public static void main(String[] argv) {
        int register = 0;
        byte[] seed = {(byte) 0b10101010,
                (byte) 0b11110000,
                (byte) 0b00001111,
                (byte) 0b01010101};

        register = initRegisterInt(seed);
        System.out.println("20 pseudo bytes Int:");
        byte[] pseudoBytes20 = generatePseudoBytesInt(register, 20);
        printBytes(pseudoBytes20);
        System.out.println();

        register = initRegisterInt(seed);
        System.out.println("50 pseudo bytes Int:");
        byte[] pseudoBytes50 = generatePseudoBytesInt(register, 50);
        printBytes(pseudoBytes50);
        System.out.println();

        BitSet registerBitSet = initRegisterBitSet(seed);
        System.out.println("\n20 pseudo bytes BitSet:");
        byte[] pseudoBytes20BitSet = generatePseudoBytesBitSet(registerBitSet, 20);
        printBytes(pseudoBytes20BitSet);
        System.out.println();

        registerBitSet = initRegisterBitSet(seed);
        System.out.println("50 pseudo bytes BitSet:");
        byte[] pseudoBytes50BitSet = generatePseudoBytesBitSet(registerBitSet, 50);
        printBytes(pseudoBytes50BitSet);
        System.out.println();
    }
}