package com.example.packetviewer.is2.database;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import com.example.packetviewer.is2.analysis.FakeIpAnalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Local persistent storage layer (SQLite via SQLiteOpenHelper) for the IS2
 * section.
 *
 * Responsibilities:
 *  1. Create/upgrade the "tested_ips" table (one row per analysed address,
 *     holding its fuzzy suspicion score and verdict)
 *  2. Per-subnet duplicate lookup by canonical address form + prefix length
 *  3. Insert a new result or update an existing one (upsert)
 *  4. Extract the full history for the History tab
 *  5. Delete one entry / clear all history
 */
public class IPDatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "TestedIPs.db";
    private static final int DATABASE_VERSION = 3; // v2: score + verdict, v3: subnet (prefix_len, network) and per-subnet uniqueness

    public static final String TABLE_NAME = "tested_ips";
    public static final String COLUMN_ID = "id";
    public static final String COLUMN_IP = "ip_address";
    public static final String COLUMN_PREFIX = "prefix_len";       // -1 = stored before subnetting existed
    public static final String COLUMN_NETWORK = "network";         // network address of the subnet, "" if unknown
    public static final String COLUMN_TYPE = "protocol_type";      // "IPv4" or "IPv6"
    public static final String COLUMN_TIMESTAMP = "tested_at";
    public static final String COLUMN_SCORE = "risk_score";        // FIS suspicion score, -1 = not scored
    public static final String COLUMN_VERDICT = "verdict";         // e.g. "SUSPICIOUS"

    private static final String[] ALL_COLUMNS = {
            COLUMN_ID, COLUMN_IP, COLUMN_TYPE, COLUMN_TIMESTAMP, COLUMN_SCORE, COLUMN_VERDICT,
            COLUMN_PREFIX, COLUMN_NETWORK
    };

    public IPDatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(DbSchema.CREATE_V3);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        // Keep the user's stored IPs through every step.
        if (oldVersion < 2) {
            for (String sql : DbSchema.V1_TO_V2) db.execSQL(sql);
        }
        if (oldVersion < 3) {
            db.beginTransaction();
            try {
                for (String sql : DbSchema.V2_TO_V3) db.execSQL(sql);
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        }
    }

    /** One stored row. toString() is what the History ListView displays. */
    public static class HistoryEntry {
        public final long id;
        public final String ipAddress;
        public final String protocolType;
        public final String testedAt;
        public final double riskScore;   // < 0 when the row was stored before scoring existed
        public final String verdict;
        public final int prefixLen;     // -1 = unknown (older row)
        public final String network;

        public HistoryEntry(long id, String ipAddress, String protocolType, String testedAt,
                            double riskScore, String verdict, int prefixLen, String network) {
            this.prefixLen = prefixLen;
            this.network = network == null ? "" : network;
            this.id = id;
            this.ipAddress = ipAddress;
            this.protocolType = protocolType;
            this.testedAt = testedAt;
            this.riskScore = riskScore;
            this.verdict = verdict;
        }

        public boolean isScored() {
            return riskScore >= 0 && verdict != null && !verdict.isEmpty();
        }

        public String verdictText() {
            return isScored()
                    ? String.format(Locale.US, "%s (%.0f / 100)", verdict, riskScore)
                    : "not scored (stored by an older version)";
        }

        /** e.g. "  /26  (net 192.168.1.64)" or "" for rows stored before subnetting. */
        public String subnetText() {
            return prefixLen < 0 ? "" : "  /" + prefixLen + "  (net " + network + ")";
        }

        @Override
        public String toString() {
            return "[" + protocolType + "]  " + ipAddress + subnetText() + "\n" + verdictText() + "  |  " + testedAt;
        }
    }

    // =========================================================================
    // 1. EXACT LOOKUP (duplicate check). Compares the CANONICAL form, so
    //    "2001:db8::1" and its fully-expanded equivalent are the same entry.
    // =========================================================================
    /**
     * The duplicate check is PER SUBNET: the same address under a different
     * prefix is a different entry. A row stored before subnetting existed
     * (prefix_len = -1) counts as a match and is upgraded on the next save.
     */
    public HistoryEntry findByIp(String rawIpAddress, int prefixLen) {
        String key = canonicalKey(rawIpAddress);
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME, ALL_COLUMNS,
                COLUMN_IP + "=? AND (" + COLUMN_PREFIX + "=? OR " + COLUMN_PREFIX + "=-1)",
                new String[]{key, String.valueOf(prefixLen)}, null, null,
                COLUMN_PREFIX + " DESC");
        HistoryEntry entry = null;
        if (cursor.moveToFirst()) {
            entry = fromCursor(cursor);
        }
        cursor.close(); // always close cursor to avoid leaks
        return entry;
    }

    /** Other addresses already analysed in the same subnet (excluding the given one). */
    public List<HistoryEntry> findInSubnet(String network, int prefixLen, String exceptIp) {
        List<HistoryEntry> list = new ArrayList<>();
        String except = canonicalKey(exceptIp);
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_NAME, ALL_COLUMNS,
                COLUMN_NETWORK + "=? AND " + COLUMN_PREFIX + "=? AND " + COLUMN_IP + "<>?",
                new String[]{network, String.valueOf(prefixLen), except}, null, null,
                COLUMN_TIMESTAMP + " DESC, " + COLUMN_ID + " DESC");
        while (cursor.moveToNext()) list.add(fromCursor(cursor));
        cursor.close();
        return list;
    }

    // =========================================================================
    // 2. SAVE A RESULT: insert a new row, or refresh the stored score, verdict,
    //    subnet and time when the address was analysed before in this subnet.
    // =========================================================================
    public boolean saveResult(String rawIpAddress, String protocolType, int prefixLen, String network,
                              double score, String verdict) {
        String key = canonicalKey(rawIpAddress);
        SQLiteDatabase db = this.getWritableDatabase();

        HistoryEntry existing = findByIp(key, prefixLen);
        if (existing != null) {
            db.execSQL("UPDATE " + TABLE_NAME + " SET "
                            + COLUMN_SCORE + "=?, " + COLUMN_VERDICT + "=?, " + COLUMN_TYPE + "=?, "
                            + COLUMN_PREFIX + "=?, " + COLUMN_NETWORK + "=?, "
                            + COLUMN_TIMESTAMP + "=CURRENT_TIMESTAMP WHERE " + COLUMN_ID + "=?",
                    new Object[]{score, verdict, protocolType, prefixLen, network, existing.id});
            return true;
        }

        ContentValues values = new ContentValues();
        values.put(COLUMN_IP, key);
        values.put(COLUMN_PREFIX, prefixLen);
        values.put(COLUMN_NETWORK, network);
        values.put(COLUMN_TYPE, protocolType);
        values.put(COLUMN_SCORE, score);
        values.put(COLUMN_VERDICT, verdict);
        return db.insert(TABLE_NAME, null, values) != -1;
    }

    // =========================================================================
    // 3. EXTRACT ALL HISTORY (for HistoryFragment ListView), most recently
    //    analysed first.
    // =========================================================================
    public List<HistoryEntry> getAllHistoryEntries() {
        List<HistoryEntry> entries = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();

        Cursor cursor = db.query(TABLE_NAME, ALL_COLUMNS, null, null, null, null,
                COLUMN_TIMESTAMP + " DESC, " + COLUMN_ID + " DESC");

        if (cursor.moveToFirst()) {
            do {
                entries.add(fromCursor(cursor));
            } while (cursor.moveToNext());
        }
        cursor.close();
        return entries;
    }

    // =========================================================================
    // 4. DELETE ONE STORED IP (long-press in History tab) / CLEAR ALL
    // =========================================================================
    public boolean deleteTestedIP(long id) {
        SQLiteDatabase db = this.getWritableDatabase();
        int rowsDeleted = db.delete(TABLE_NAME, COLUMN_ID + "=?", new String[]{String.valueOf(id)});
        return rowsDeleted > 0;
    }

    public void clearAllHistory() {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(TABLE_NAME, null, null);
    }

    // =========================================================================
    // 5. GET COUNT (handy for stats / viva demo)
    // =========================================================================
    public int getTestedCount() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_NAME, null);
        int count = 0;
        if (cursor.moveToFirst()) {
            count = cursor.getInt(0);
        }
        cursor.close();
        return count;
    }

    // ------------------------------------------------------------------

    private static HistoryEntry fromCursor(Cursor c) {
        return new HistoryEntry(
                c.getLong(0),
                c.getString(1),
                c.getString(2),
                c.getString(3),
                c.getDouble(4),
                c.getString(5),
                c.getInt(6),
                c.getString(7));
    }

    /** The single form an address is stored under; unparseable text is stored trimmed as-is. */
    private static String canonicalKey(String raw) {
        String canonical = FakeIpAnalyzer.canonicalForm(raw);
        if (canonical != null) return canonical;
        return raw == null ? "" : raw.trim();
    }
}
