package ch.token2.fido2;

import javacard.framework.APDU;
import javacard.framework.JCSystem;

/**
 * Static scratch layout for hot FIDO2 paths.
 */
public final class TransientScratch {

    public static final short RP_HASH_LEN = (short) 32;
    public static final short CLIENT_DATA_HASH_LEN = (short) 32;
    public static final short PUB_KEY_LEN = (short) 65;
    public static final short HMAC_SALT_LEN = (short) 64;
    private static final short HMAC_SALT_STATE_LEN = (short) 1;

    private static final short OFFSET_RP_HASH = (short) 0;
    private static final short OFFSET_CLIENT_DATA_HASH = (short) (OFFSET_RP_HASH + RP_HASH_LEN);
    private static final short OFFSET_PUB_KEY = (short) (OFFSET_CLIENT_DATA_HASH + CLIENT_DATA_HASH_LEN);
    private static final short OFFSET_HMAC_SALT = (short) (OFFSET_PUB_KEY + PUB_KEY_LEN);
    private static final short TOTAL_LEN = (short) (OFFSET_HMAC_SALT + HMAC_SALT_STATE_LEN + HMAC_SALT_LEN);

    private static byte[] scratch;

    private TransientScratch() {
    }

    public static void initialize() {
        if (scratch == null) {
            scratch = JCSystem.makeTransientByteArray(TOTAL_LEN, JCSystem.CLEAR_ON_DESELECT);
        }
    }

    public static byte[] getBuffer() {
        return scratch;
    }

    public static short getRpHashOffset() {
        return OFFSET_RP_HASH;
    }

    public static short getClientDataHashOffset() {
        return OFFSET_CLIENT_DATA_HASH;
    }

    public static short getPubKeyOffset() {
        return OFFSET_PUB_KEY;
    }

    public static short getHmacSaltOffset() {
        return OFFSET_HMAC_SALT;
    }

    public static byte[] getApduOrBufferMem(APDU apdu, short requiredLen, byte[] bufferMem) {
        byte[] apduBuffer = apdu.getBuffer();
        if (requiredLen <= (short) apduBuffer.length) {
            return apduBuffer;
        }
        return bufferMem;
    }
}