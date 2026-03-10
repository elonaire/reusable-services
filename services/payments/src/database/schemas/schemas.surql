-- Enable GraphQL
-- DEFINE CONFIG GRAPHQL AUTO;
-- Analyzer
DEFINE ANALYZER currency_analyzer TOKENIZERS blank,class,camel,punct FILTERS edgengram(2, 10), lowercase;

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
DEFINE INDEX currencyNameIndex ON TABLE currency FIELDS name SEARCH ANALYZER currency_analyzer BM25(1.2,0.75) HIGHLIGHTS;
