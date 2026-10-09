-- Enable GraphQL
-- DEFINE CONFIG GRAPHQL AUTO;

-- A schema-full user_id table
DEFINE TABLE user_id SCHEMAFULL;
-- define some fields
DEFINE FIELD user_id ON TABLE user_id TYPE string;
DEFINE INDEX userIndex ON TABLE user_id COLUMNS user_id UNIQUE;

-- A schema-full file table
DEFINE TABLE file SCHEMAFULL;
DEFINE FIELD name ON TABLE file TYPE string;
DEFINE FIELD system_filename ON TABLE file TYPE string;
DEFINE FIELD OVERWRITE size ON TABLE file TYPE int;
DEFINE FIELD is_premium ON TABLE file TYPE bool DEFAULT false;
DEFINE FIELD is_public ON TABLE file TYPE bool DEFAULT false;
DEFINE FIELD mime_type ON TABLE file TYPE string;
DEFINE FIELD owner ON TABLE file TYPE record<user_id>;
DEFINE FIELD created_at ON TABLE file TYPE datetime
  DEFAULT time::now() READONLY;

-- Relationship between user_id and file
DEFINE TABLE bought SCHEMAFULL TYPE RELATION IN user_id OUT file;
DEFINE INDEX fileIndex ON TABLE bought
    COLUMNS in, out UNIQUE;

-- Bucket: top-level container
DEFINE TABLE bucket SCHEMAFULL;
DEFINE FIELD name ON TABLE bucket TYPE string;   -- globally unique
DEFINE INDEX bucketNameIndex ON TABLE bucket FIELDS name UNIQUE;
DEFINE FIELD owner ON TABLE bucket TYPE record<user_id>;
DEFINE FIELD is_public ON TABLE bucket TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE storage_class ON TABLE bucket TYPE
    { Standard: object }
  | { Nearline: object }
  | { Coldline: object }
  | { Archive: object }
  DEFAULT { Standard: {} };
DEFINE FIELD is_premium ON TABLE bucket TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE bucket TYPE datetime DEFAULT time::now() READONLY;

-- Key: (more like a folder)
DEFINE TABLE key SCHEMAFULL;
DEFINE FIELD name ON TABLE key TYPE string;
DEFINE FIELD owner ON TABLE key TYPE record<user_id>;
DEFINE FIELD is_public ON TABLE key TYPE bool DEFAULT false;
DEFINE FIELD created_at ON TABLE key TYPE datetime DEFAULT time::now() READONLY;

-- Relationship between bucket, key, and file
DEFINE TABLE OVERWRITE belongs_to SCHEMAFULL TYPE RELATION IN file | key OUT key | bucket;

DEFINE TABLE bucket_stats SCHEMAFULL;
DEFINE FIELD bucket ON TABLE bucket_stats TYPE record<bucket>;
DEFINE FIELD hits ON TABLE bucket_stats TYPE int DEFAULT 0;
DEFINE FIELD bytes_served ON TABLE bucket_stats TYPE int DEFAULT 0;
DEFINE FIELD OVERWRITE last_accessed ON TABLE bucket_stats TYPE datetime VALUE time::now();
DEFINE FIELD created_at ON TABLE bucket_stats TYPE datetime DEFAULT time::now() READONLY;

DEFINE INDEX bucketStatsIndex ON bucket_stats FIELDS bucket, created_at UNIQUE;

-- A long-running upload session
DEFINE TABLE upload_session SCHEMAFULL;
DEFINE FIELD user ON TABLE upload_session TYPE record<user_id>;
DEFINE FIELD upload_id ON TABLE upload_session TYPE string;
DEFINE FIELD file_name ON TABLE upload_session TYPE string;   -- what the client called it
DEFINE FIELD total_size ON TABLE upload_session TYPE int;
DEFINE FIELD mime_type ON TABLE upload_session TYPE string;
DEFINE FIELD bucket ON TABLE upload_session TYPE record<bucket>;
DEFINE FIELD key ON TABLE upload_session TYPE option<record<key>>;
DEFINE FIELD bucket_path ON TABLE upload_session TYPE string;   -- for logs/debugging
DEFINE FIELD part_size ON TABLE upload_session TYPE int;
DEFINE FIELD total_parts ON TABLE upload_session TYPE int;
DEFINE FIELD status ON TABLE upload_session TYPE
    { InProgress: object }
  | { Completed: object }
  | { Aborted: object };
DEFINE FIELD created_at ON TABLE upload_session TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD completed_at ON TABLE upload_session TYPE option<datetime>;
DEFINE INDEX uploadSessionIdIndex ON TABLE upload_session FIELDS upload_id UNIQUE;

DEFINE EVENT upload_completed ON TABLE upload_session WHEN $event = 'UPDATE' THEN {
    IF $after.status.Completed != NONE && $before.status.Completed = NONE {
        UPDATE $after.id SET completed_at = time::now();
    };
};

-- One row per received part; the disk blob is named by system_filename (flat)
DEFINE TABLE upload_part SCHEMAFULL;
DEFINE FIELD session ON TABLE upload_part TYPE record<upload_session>;
DEFINE FIELD part_number ON TABLE upload_part TYPE int;
DEFINE FIELD system_filename ON TABLE upload_part TYPE string;   -- flat filename on disk
DEFINE FIELD size ON TABLE upload_part TYPE int;
DEFINE FIELD etag ON TABLE upload_part TYPE string;
DEFINE FIELD received_at ON TABLE upload_part TYPE datetime DEFAULT time::now() READONLY;
DEFINE INDEX uploadPartIndex ON TABLE upload_part FIELDS session, part_number UNIQUE;


/* Migrations */
UPDATE bucket SET is_premium = false WHERE is_premium = NONE;
UPDATE file SET is_premium = false WHERE is_premium = NONE;
UPDATE file SET is_premium = !is_free WHERE is_premium = NONE;
REMOVE FIELD is_free ON TABLE file;
UPDATE file UNSET is_free;
