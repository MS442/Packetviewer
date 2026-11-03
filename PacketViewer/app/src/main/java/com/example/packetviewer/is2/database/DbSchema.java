package com.example.packetviewer.is2.database;

/**
 * The SQL of the tested_ips table, kept free of Android classes so the
 * migration can be tested on a desktop SQLite.
 *
 * v3: an address is unique PER SUBNET: UNIQUE(ip_address, prefix_len).
 * prefix_len = -1 marks rows stored before subnetting existed.
 */
public final class DbSchema {

    private DbSchema() { }

    public static final String TABLE = "tested_ips";

    public static final String CREATE_V3 =
            "CREATE TABLE tested_ips (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
            "ip_address TEXT NOT NULL, " +
            "prefix_len INTEGER NOT NULL DEFAULT -1, " +
            "network TEXT NOT NULL DEFAULT '', " +
            "protocol_type TEXT NOT NULL, " +
            "tested_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
            "risk_score REAL DEFAULT -1, " +
            "verdict TEXT DEFAULT '', " +
            "UNIQUE(ip_address, prefix_len))";

    /** v1 -> v2 (columns added to the old table). */
    public static final String[] V1_TO_V2 = {
            "ALTER TABLE tested_ips ADD COLUMN risk_score REAL DEFAULT -1",
            "ALTER TABLE tested_ips ADD COLUMN verdict TEXT DEFAULT ''"
    };

    /** v2 -> v3: SQLite cannot change a UNIQUE constraint, so rebuild the table and copy the rows. */
    public static final String[] V2_TO_V3 = {
            "ALTER TABLE tested_ips RENAME TO tested_ips_old",
            CREATE_V3,
            "INSERT INTO tested_ips (id, ip_address, prefix_len, network, protocol_type, tested_at, risk_score, verdict) " +
                    "SELECT id, ip_address, -1, '', protocol_type, tested_at, risk_score, verdict FROM tested_ips_old",
            "DROP TABLE tested_ips_old"
    };
}
