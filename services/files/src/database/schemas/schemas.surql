-- Enable GraphQL
DEFINE CONFIG GRAPHQL AUTO;

-- A schema-full user_id table
DEFINE TABLE user_id SCHEMAFULL;
-- define some fields
DEFINE FIELD user_id ON TABLE user_id TYPE string;
DEFINE INDEX userIndex ON TABLE user_id COLUMNS user_id UNIQUE;

-- A schema-full product_id table
DEFINE TABLE product_id SCHEMAFULL;
-- define some fields
DEFINE FIELD product_id ON TABLE product_id TYPE string;
DEFINE INDEX productIndex ON TABLE product_id COLUMNS product_id UNIQUE;

-- A schema-full license_id table
DEFINE TABLE license_id SCHEMAFULL;
-- define some fields
DEFINE FIELD license_id ON TABLE license_id TYPE string;
DEFINE INDEX productIndex ON TABLE license_id COLUMNS license_id UNIQUE;

-- A schema-full file table
DEFINE TABLE file SCHEMAFULL;
DEFINE FIELD name ON TABLE file TYPE string;
DEFINE FIELD system_filename ON TABLE file TYPE string;
DEFINE FIELD size ON TABLE file TYPE number;
DEFINE FIELD is_free ON TABLE file TYPE bool DEFAULT true;
DEFINE FIELD mime_type ON TABLE file TYPE string;
DEFINE FIELD owner ON TABLE file TYPE record<user_id>;
DEFINE FIELD created_at ON TABLE file TYPE datetime
  DEFAULT time::now();

-- Relationship between product and file
DEFINE TABLE product_license_artifact SCHEMAFULL TYPE RELATION;
DEFINE FIELD license ON TABLE product_license_artifact TYPE record<license_id>;
DEFINE INDEX fileIndex ON TABLE product_license_artifact
COLUMNS in, out, license UNIQUE;
DEFINE FIELD in ON TABLE product_license_artifact TYPE record<product_id>;
DEFINE FIELD out ON TABLE product_license_artifact TYPE record<file>;

-- Relationship between product and file
DEFINE TABLE bought_file SCHEMAFULL TYPE RELATION;
DEFINE INDEX fileIndex ON TABLE bought_file
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE bought_file TYPE record<user_id>;
DEFINE FIELD out ON TABLE bought_file TYPE record<file>;

/* Migrations */
-- Migration for file table
UPDATE file SET system_filename = "" WHERE system_filename IS NONE;

-- Migration for file table
UPDATE file SET is_free = true WHERE is_free IS NONE;
