-- Enable GraphQL
-- DEFINE CONFIG GRAPHQL AUTO;
-- Analyzer
-- edgengram splits words into n-grams for full-text search by backtracking through the tokenizer e.g apple -> ['ap','app','appl','apple']
DEFINE ANALYZER OVERWRITE currency_analyzer TOKENIZERS blank, camel, punct, class FILTERS edgengram(2, 10), lowercase;

-- A schema-full user_id table
DEFINE TABLE user_id SCHEMAFULL;
-- define some fields
DEFINE FIELD user_id ON TABLE user_id TYPE string;
DEFINE INDEX userIndex ON TABLE user_id COLUMNS user_id UNIQUE;

-- A schema-full currency table.
DEFINE TABLE currency SCHEMAFULL TYPE NORMAL;
DEFINE FIELD code ON TABLE currency TYPE string;
DEFINE FIELD numeric ON TABLE currency TYPE string;
DEFINE FIELD name ON TABLE currency TYPE string;
DEFINE FIELD symbol ON TABLE currency TYPE string;
DEFINE FIELD flag ON TABLE currency TYPE string;
DEFINE INDEX currencyIndex ON TABLE currency COLUMNS code, numeric UNIQUE;
DEFINE FIELD created_at ON TABLE currency TYPE datetime
    DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE currency TYPE datetime
    VALUE time::now();
--Full-text search
DEFINE INDEX OVERWRITE currencyNameIndex ON TABLE currency FIELDS name FULLTEXT ANALYZER currency_analyzer BM25 HIGHLIGHTS;

/* Migrations */
REBUILD INDEX currencyNameIndex ON TABLE currency;
