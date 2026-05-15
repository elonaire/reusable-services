-- Subscribers
DEFINE TABLE OVERWRITE subscriber SCHEMAFULL;

DEFINE FIELD email ON TABLE subscriber TYPE string ASSERT string::is_email($value);
DEFINE FIELD first_name ON TABLE subscriber TYPE option<string>;
DEFINE FIELD last_name ON TABLE subscriber TYPE option<string>;

DEFINE FIELD OVERWRITE status ON TABLE subscriber TYPE
    { Active: object }
  | { Unsubscribed: object }
  | { Bounced: object }

  DEFAULT { Active: {} };
DEFINE INDEX subscriberIndex ON TABLE subscriber COLUMNS email UNIQUE;
DEFINE FIELD OVERWRITE created_at ON TABLE subscriber TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE subscriber TYPE datetime VALUE time::now();

-- Mailing List
DEFINE TABLE mailing_list SCHEMAFULL;

DEFINE FIELD name ON TABLE mailing_list TYPE string;
DEFINE FIELD description ON TABLE mailing_list TYPE option<string>;
DEFINE FIELD created_at ON TABLE mailing_list TYPE datetime DEFAULT time::now();

-- Subscription - subscriber subscribes to a mailing List
DEFINE TABLE OVERWRITE subscription TYPE RELATION IN subscriber OUT mailing_list;
DEFINE INDEX mailingListSubscriptionIndex ON TABLE subscription COLUMNS in, out UNIQUE;
DEFINE FIELD OVERWRITE created_at ON TABLE subscription TYPE datetime DEFAULT time::now() READONLY;

-- Email Templates
DEFINE TABLE email_template SCHEMAFULL;

DEFINE FIELD name ON TABLE email_template TYPE string;
DEFINE FIELD subject ON TABLE email_template TYPE string;

DEFINE FIELD html ON TABLE email_template TYPE string;

DEFINE FIELD variables ON TABLE email_template TYPE array<string>;
DEFINE FIELD attachments ON TABLE email_template TYPE array<{ url: string, filename: string, content_type: string, inline: bool, cid: option<string> }>;

DEFINE FIELD OVERWRITE created_at ON TABLE email_template TYPE datetime DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE email_template TYPE datetime VALUE time::now();

-- Email Campaigns
DEFINE TABLE campaign SCHEMAFULL;

DEFINE FIELD name ON TABLE campaign TYPE string;

DEFINE FIELD template ON TABLE campaign TYPE record<email_template>;
DEFINE FIELD list ON TABLE campaign TYPE record<mailing_list>;

DEFINE FIELD OVERWRITE status ON TABLE campaign TYPE
    { Draft: object }
  | { Scheduled: object }
  | { Sending: object }
  | { Sent: object }

  DEFAULT { Draft: {} };

DEFINE FIELD scheduled_at ON TABLE campaign TYPE option<datetime>;

DEFINE FIELD OVERWRITE created_at ON TABLE campaign TYPE datetime DEFAULT time::now() READONLY;

/* Migrations */
UPDATE subscriber SET
  status = IF status = 'Active' THEN { Active: {} }
    ELSE IF status = 'Unsubscribed' THEN { Unsubscribed: {} }
    ELSE IF status = 'Bounced' THEN { Bounced: {} }
    ELSE status
  END;
