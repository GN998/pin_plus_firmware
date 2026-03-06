package ch.token2.fido2;

import javacard.framework.Util;

/**
 * Zero-allocation CBOR reader for CTAP2 request parsing.
 */
public final class CBORReader {

    public static final short OK = (short) 0;
    public static final short ERR_INVALID = (short) -1;
    public static final short ERR_BOUNDS = (short) -2;
    public static final short ERR_UNEXPECTED_TYPE = (short) -3;
    public static final short ERR_STATE = (short) -4;
    public static final short ERR_RANGE = (short) -5;
    public static final short ERR_NO_DATA = (short) -6;
    public static final short ERR_DONE = (short) -7;

    public static final short INDEFINITE_LENGTH = (short) -1;

    private static final byte MAJOR_UNSIGNED = (byte) 0;
    private static final byte MAJOR_NEGATIVE = (byte) 1;
    private static final byte MAJOR_BYTES = (byte) 2;
    private static final byte MAJOR_TEXT = (byte) 3;
    private static final byte MAJOR_ARRAY = (byte) 4;
    private static final byte MAJOR_MAP = (byte) 5;
    private static final byte MAJOR_TAG = (byte) 6;
    private static final byte MAJOR_SIMPLE = (byte) 7;

    private static final byte BREAK_MARKER = (byte) 0xFF;

    private byte[] buffer;
    private short cursor;
    private short end;

    private short mapRemaining;
    private boolean mapIndefinite;
    private boolean mapActive;
    private boolean mapAwaitingValue;

    private short decodedValue;
    private short decodedHeadLen;
    private boolean decodedIndefinite;

    public CBORReader() {
    }

    public short init(byte[] inBuffer, short inOffset, short inLength) {
        if (inBuffer == null || inOffset < (short) 0 || inLength < (short) 0) {
            return ERR_BOUNDS;
        }
        if (inOffset > (short) inBuffer.length) {
            return ERR_BOUNDS;
        }
        if (!canAdd(inOffset, inLength, (short) inBuffer.length)) {
            return ERR_BOUNDS;
        }

        buffer = inBuffer;
        cursor = inOffset;
        end = (short) (inOffset + inLength);
        mapRemaining = (short) 0;
        mapIndefinite = false;
        mapActive = false;
        mapAwaitingValue = false;
        return OK;
    }

    public short readMapHeader() {
        if (buffer == null) {
            return ERR_STATE;
        }
        if (cursor >= end) {
            return ERR_NO_DATA;
        }

        byte first = buffer[cursor];
        byte major = majorType(first);
        if (major != MAJOR_MAP) {
            return ERR_UNEXPECTED_TYPE;
        }

        short status = decodeAdditional(cursor, end, major);
        if (status != OK) {
            return status;
        }

        cursor = (short) (cursor + decodedHeadLen);
        mapActive = true;
        mapAwaitingValue = false;

        if (decodedIndefinite) {
            mapIndefinite = true;
            mapRemaining = INDEFINITE_LENGTH;
            return INDEFINITE_LENGTH;
        }

        mapIndefinite = false;
        mapRemaining = decodedValue;
        return mapRemaining;
    }

    public short readNextKey() {
        if (!mapActive) {
            return ERR_STATE;
        }
        if (mapAwaitingValue) {
            return ERR_STATE;
        }

        if (mapIndefinite) {
            if (cursor >= end) {
                return ERR_BOUNDS;
            }
            if (buffer[cursor] == BREAK_MARKER) {
                cursor++;
                mapActive = false;
                return ERR_DONE;
            }
        } else {
            if (mapRemaining == (short) 0) {
                mapActive = false;
                return ERR_DONE;
            }
        }

        short key = readShortInteger();
        if (key < (short) 0) {
            return key;
        }

        mapAwaitingValue = true;
        return key;
    }

    public short skipValue() {
        short status = skipItem();
        if (status != OK) {
            return status;
        }

        if (mapActive && mapAwaitingValue) {
            mapAwaitingValue = false;
            if (!mapIndefinite) {
                mapRemaining--;
            }
        }
        return OK;
    }

    public short readBytes(byte[] out, short outOff) {
        if (out == null) {
            return ERR_BOUNDS;
        }
        if (cursor >= end) {
            return ERR_NO_DATA;
        }

        byte first = buffer[cursor];
        byte major = majorType(first);
        if (major != MAJOR_BYTES) {
            return ERR_UNEXPECTED_TYPE;
        }

        short status = decodeAdditional(cursor, end, major);
        if (status != OK) {
            return status;
        }

        short written = (short) 0;
        if (!decodedIndefinite) {
            short start = (short) (cursor + decodedHeadLen);
            if (!canAdd(start, decodedValue, end)) {
                return ERR_BOUNDS;
            }
            if (!canAdd(outOff, decodedValue, (short) out.length)) {
                return ERR_BOUNDS;
            }

            Util.arrayCopyNonAtomic(buffer, start, out, outOff, decodedValue);
            cursor = (short) (start + decodedValue);
            written = decodedValue;
        } else {
            cursor = (short) (cursor + decodedHeadLen);
            while (true) {
                if (cursor >= end) {
                    return ERR_BOUNDS;
                }
                if (buffer[cursor] == BREAK_MARKER) {
                    cursor++;
                    break;
                }

                first = buffer[cursor];
                major = majorType(first);
                if (major != MAJOR_BYTES) {
                    return ERR_INVALID;
                }

                status = decodeAdditional(cursor, end, major);
                if (status != OK || decodedIndefinite) {
                    return ERR_INVALID;
                }

                short partStart = (short) (cursor + decodedHeadLen);
                if (!canAdd(partStart, decodedValue, end)) {
                    return ERR_BOUNDS;
                }
                if (!canAdd(outOff, decodedValue, (short) out.length)) {
                    return ERR_BOUNDS;
                }

                Util.arrayCopyNonAtomic(buffer, partStart, out, outOff, decodedValue);
                outOff = (short) (outOff + decodedValue);
                written = (short) (written + decodedValue);
                cursor = (short) (partStart + decodedValue);
            }
        }

        if (mapActive && mapAwaitingValue) {
            mapAwaitingValue = false;
            if (!mapIndefinite) {
                mapRemaining--;
            }
        }

        return written;
    }

    public short getCursor() {
        return cursor;
    }

    private short readShortInteger() {
        if (cursor >= end) {
            return ERR_NO_DATA;
        }

        byte first = buffer[cursor];
        byte major = majorType(first);
        if (major != MAJOR_UNSIGNED && major != MAJOR_NEGATIVE) {
            return ERR_UNEXPECTED_TYPE;
        }

        short status = decodeAdditional(cursor, end, major);
        if (status != OK || decodedIndefinite) {
            return ERR_INVALID;
        }

        cursor = (short) (cursor + decodedHeadLen);

        if (major == MAJOR_UNSIGNED) {
            if (decodedValue < (short) 0) {
                return ERR_RANGE;
            }
            return decodedValue;
        }

        if (decodedValue > (short) 32767) {
            return ERR_RANGE;
        }
        return (short) (-1 - decodedValue);
    }

    private short skipItem() {
        if (cursor >= end) {
            return ERR_NO_DATA;
        }

        byte first = buffer[cursor];
        byte major = majorType(first);

        short status = decodeAdditional(cursor, end, major);
        if (status != OK) {
            return status;
        }

        short headEnd = (short) (cursor + decodedHeadLen);

        if (major == MAJOR_UNSIGNED || major == MAJOR_NEGATIVE) {
            cursor = headEnd;
            return OK;
        }

        if (major == MAJOR_BYTES || major == MAJOR_TEXT) {
            if (!decodedIndefinite) {
                if (!canAdd(headEnd, decodedValue, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + decodedValue);
                return OK;
            }

            cursor = headEnd;
            while (true) {
                if (cursor >= end) {
                    return ERR_BOUNDS;
                }
                if (buffer[cursor] == BREAK_MARKER) {
                    cursor++;
                    return OK;
                }

                first = buffer[cursor];
                if (majorType(first) != major) {
                    return ERR_INVALID;
                }

                status = decodeAdditional(cursor, end, major);
                if (status != OK || decodedIndefinite) {
                    return ERR_INVALID;
                }

                headEnd = (short) (cursor + decodedHeadLen);
                if (!canAdd(headEnd, decodedValue, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + decodedValue);
            }
        }

        if (major == MAJOR_ARRAY) {
            cursor = headEnd;
            if (!decodedIndefinite) {
                short count = decodedValue;
                while (count > (short) 0) {
                    status = skipItem();
                    if (status != OK) {
                        return status;
                    }
                    count--;
                }
                return OK;
            }

            while (true) {
                if (cursor >= end) {
                    return ERR_BOUNDS;
                }
                if (buffer[cursor] == BREAK_MARKER) {
                    cursor++;
                    return OK;
                }
                status = skipItem();
                if (status != OK) {
                    return status;
                }
            }
        }

        if (major == MAJOR_MAP) {
            cursor = headEnd;
            if (!decodedIndefinite) {
                short pairCount = decodedValue;
                while (pairCount > (short) 0) {
                    status = skipItem();
                    if (status != OK) {
                        return status;
                    }
                    status = skipItem();
                    if (status != OK) {
                        return status;
                    }
                    pairCount--;
                }
                return OK;
            }

            while (true) {
                if (cursor >= end) {
                    return ERR_BOUNDS;
                }
                if (buffer[cursor] == BREAK_MARKER) {
                    cursor++;
                    return OK;
                }
                status = skipItem();
                if (status != OK) {
                    return status;
                }
                status = skipItem();
                if (status != OK) {
                    return status;
                }
            }
        }

        if (major == MAJOR_TAG) {
            cursor = headEnd;
            return skipItem();
        }

        if (major == MAJOR_SIMPLE) {
            if (decodedIndefinite) {
                return ERR_INVALID;
            }
            if (decodedValue <= (short) 23) {
                cursor = headEnd;
                return OK;
            }
            if (decodedValue == (short) 24) {
                if (!canAdd(headEnd, (short) 1, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + 1);
                return OK;
            }
            if (decodedValue == (short) 25) {
                if (!canAdd(headEnd, (short) 2, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + 2);
                return OK;
            }
            if (decodedValue == (short) 26) {
                if (!canAdd(headEnd, (short) 4, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + 4);
                return OK;
            }
            if (decodedValue == (short) 27) {
                if (!canAdd(headEnd, (short) 8, end)) {
                    return ERR_BOUNDS;
                }
                cursor = (short) (headEnd + 8);
                return OK;
            }
            return ERR_INVALID;
        }

        return ERR_INVALID;
    }

    private short decodeAdditional(short at, short limit, byte major) {
        if (at >= limit) {
            return ERR_BOUNDS;
        }

        byte first = buffer[at];
        short ai = (short) (first & (byte) 0x1F);

        decodedIndefinite = false;
        decodedValue = (short) 0;

        if (ai <= (short) 23) {
            decodedHeadLen = (short) 1;
            decodedValue = ai;
            return OK;
        }

        if (ai == (short) 24) {
            if (!canAdd(at, (short) 2, limit)) {
                return ERR_BOUNDS;
            }
            decodedHeadLen = (short) 2;
            decodedValue = (short) (buffer[(short) (at + 1)] & (short) 0xFF);
            return OK;
        }

        if (ai == (short) 25) {
            if (major == MAJOR_SIMPLE) {
                decodedHeadLen = (short) 1;
                decodedValue = ai;
                return OK;
            }
            if (!canAdd(at, (short) 3, limit)) {
                return ERR_BOUNDS;
            }
            decodedHeadLen = (short) 3;
            if (buffer[(short) (at + 1)] < (byte) 0) {
                return ERR_RANGE;
            }
            decodedValue = Util.getShort(buffer, (short) (at + 1));
            if (decodedValue < (short) 0) {
                return ERR_RANGE;
            }
            return OK;
        }

        if (ai == (short) 31) {
            decodedHeadLen = (short) 1;
            decodedIndefinite = true;
            return OK;
        }

        return ERR_RANGE;
    }

    private static byte majorType(byte initialByte) {
        return (byte) (((short) (initialByte & (short) 0xFF)) >> 5);
    }

    private static boolean canAdd(short base, short add, short limit) {
        if (add < (short) 0 || base < (short) 0 || limit < (short) 0) {
            return false;
        }
        if (base > limit) {
            return false;
        }
        if (add > (short) (limit - base)) {
            return false;
        }
        return true;
    }
}
