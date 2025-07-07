package ro.ase.ism.sap.DAY04;

public class Utility {
    public static String getHex(byte[] values) {
        StringBuilder sb = new StringBuilder();
        for(byte b : values) {
            sb.append(String.format(" %02x", b));
        }
        return sb.toString();
    }
}