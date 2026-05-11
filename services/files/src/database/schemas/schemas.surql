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
DEFINE FIELD is_free ON TABLE file TYPE bool DEFAULT true;
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


/* Migrations */
-- Migration for file table
-- UPDATE file SET system_filename = "" WHERE system_filename IS NONE;

-- Migration for file table
-- UPDATE file SET is_free = true WHERE is_free IS NONE;
UPDATE file SET is_public = true WHERE is_public IS NONE;
REMOVE TABLE bought_file;
CREATE bucket SET name = "default", owner = user:3ryxtyeo959ecjv1sr7t;
RELATE (SELECT VALUE id FROM file WHERE array::len(->belongs_to) = 0)->belongs_to->(SELECT VALUE id FROM ONLY bucket WHERE name="default" LIMIT 1);
UPDATE bucket SET storage_class = { Standard: {} } WHERE storage_class = 'Standard' OR storage_class = NONE;
UPDATE bucket SET storage_class = { Nearline: {} } WHERE storage_class = 'Nearline';
UPDATE bucket SET storage_class = { Coldline: {} } WHERE storage_class = 'Coldline';
UPDATE bucket SET storage_class = { Archive: {} } WHERE storage_class = 'Archive';
