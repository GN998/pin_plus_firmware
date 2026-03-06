package ch.token2.fido2;

import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;

/**
 * Static scratch layout for hot FIDO2 paths.
 *
 * Must be allocated during applet install/constructor to avoid runtime allocation.
 */
public final class TransientScratch {

    public static final short RP_HASH_LEN = (short) 32;
    public static final short CLIENT_DATA_HASH_LEN = (short) 32;
    public static final short PUB_KEY_LEN = (short) 65;
    public static final short HMAC_SALT_LEN = (short) 64;
    public static final short HMAC_SALT_STATE_LEN = (short) 1;

    private static final short OFFSET_RP_HASH = (short) 0;
    private static final short OFFSET_CLIENT_DATA_HASH = (short) (OFFSET_RP_HASH + RP_HASH_LEN);
    private static final short OFFSET_PUB_KEY = (short) (OFFSET_CLIENT_DATA_HASH + CLIENT_DATA_HASH_LEN);
    private static final short OFFSET_HMAC_SALT_STATE = (short) (OFFSET_PUB_KEY + PUB_KEY_LEN);
    private static final short OFFSET_HMAC_SALT = (short) (OFFSET_HMAC_SALT_STATE + HMAC_SALT_STATE_LEN);
    private static final short TOTAL_LEN = (short) (OFFSET_HMAC_SALT + HMAC_SALT_LEN);

    private static byte[] scratch;

    private TransientScratch() {
    }

    /**
     * Allocate once, during install/constructor only.
     */
    public static void initializeAtInstall() {
        if (scratch == null) {
            scratch = JCSystem.makeTransientByteArray(TOTAL_LEN, JCSystem.CLEAR_ON_DESELECT);
        }
    }

    public static byte[] getBuffer() {
        if (scratch == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        return scratch;
    }

    public static short getTotalLen() {
        return TOTAL_LEN;
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

    public static short getHmacSaltStateOffset() {
        return OFFSET_HMAC_SALT_STATE;
    }

    public static short getHmacSaltOffset() {
        return OFFSET_HMAC_SALT;
    }

    /**
     * APDU-first strategy: prefer APDU buffer if it is large enough, otherwise use the fallback bufferMem.
     */
    public static byte[] getApduOrBufferMem(APDU apdu, short requiredLen, byte[] bufferMem) {
        byte[] apduBuffer = apdu.getBuffer();
        if (requiredLen <= (short) apduBuffer.length) {
            return apduBuffer;
        }
        return bufferMem;
    }
}
