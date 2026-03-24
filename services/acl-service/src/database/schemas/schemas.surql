-- Enable GraphQL
-- DEFINE CONFIG GRAPHQL AUTO;

-- A schema-full user table.
DEFINE TABLE OVERWRITE user SCHEMAFULL;
-- define some fields.
DEFINE FIELD user_name ON TABLE user TYPE option<string>
    ASSERT string::matches($value, "^[a-z0-9_]+$");
DEFINE INDEX userNameIndex ON TABLE user COLUMNS user_name UNIQUE;
DEFINE FIELD first_name ON TABLE user TYPE option<string>;
DEFINE FIELD middle_name ON TABLE user TYPE option<string>;
DEFINE FIELD last_name ON TABLE user TYPE option<string>;
DEFINE FIELD gender ON TABLE user TYPE option<string>
-- Allow only these values in the array
  ASSERT $value INSIDE ['Male', 'Female', 'Other', NONE];
DEFINE FIELD dob ON TABLE user VALUE
  IF $value IS NOT NONE { <datetime>$value } ELSE { NONE };
-- DEFINE FIELD dob ON TABLE user TYPE option<datetime> VALUE time::now();
DEFINE FIELD email ON TABLE user TYPE string
  ASSERT string::is::email($value);
DEFINE INDEX userEmailIndex ON TABLE user COLUMNS email UNIQUE;
DEFINE FIELD country ON TABLE user TYPE option<string>;
DEFINE FIELD phone ON TABLE user TYPE option<string>;
  -- ASSERT string::len($value) == 10;
DEFINE INDEX userPhoneIndex ON TABLE user COLUMNS phone UNIQUE;
DEFINE FIELD password ON TABLE user TYPE option<string>
  DEFAULT NONE;
DEFINE EVENT enforce_blank_password_constraint ON TABLE user WHEN $event = 'CREATE' THEN {
    IF $after.password IS NONE AND ($after.oauth_client IS NONE OR $after.oauth_user_id IS NONE) {
        THROW 'Forbidden.';
    };
};
DEFINE EVENT user_created ON TABLE user WHEN $event = 'CREATE' THEN (
    -- add default role to user
    fn::assign_default_role($after.id)
);
DEFINE FIELD status ON TABLE user TYPE string
  DEFAULT 'Inactive'
-- Allow only these values in the array
  ASSERT $value INSIDE ['Active', 'Inactive', 'Suspended', 'Deleted'];
DEFINE FIELD oauth_client ON TABLE user TYPE option<string>
-- Allow only these values in the array
  ASSERT $value INSIDE ['Google', 'Github', NONE];
DEFINE FIELD oauth_user_id ON TABLE user TYPE option<string>
  DEFAULT NONE;
DEFINE FIELD address ON TABLE user TYPE option<string>
  DEFAULT NONE;
DEFINE FIELD profile_picture ON TABLE user TYPE option<string>
  ASSERT string::is::url($value)
  DEFAULT NONE;
DEFINE FIELD bio ON TABLE user TYPE option<string>
  DEFAULT NONE;
DEFINE FIELD website ON TABLE user TYPE option<string>
  ASSERT string::is::url($value)
  DEFAULT NONE;
DEFINE FIELD OVERWRITE socials ON TABLE user TYPE option<array<{ name: string, url: string }>>
    DEFAULT NONE;
DEFINE FIELD OVERWRITE socials[*].url ON TABLE user TYPE string
    ASSERT string::is::url($value);
DEFINE FIELD created_at ON TABLE user TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE user TYPE datetime
  VALUE time::now();

-- A schema-full role table.
DEFINE TABLE role SCHEMAFULL;
-- define some fields.
DEFINE FIELD role_name ON TABLE role TYPE string VALUE string::uppercase($value)
    ASSERT string::matches($value, "^[A-Za-z0-9_]+$");
DEFINE FIELD is_default ON TABLE role TYPE bool DEFAULT false;
DEFINE EVENT restrict_setting_default_role ON TABLE role WHEN $event  = 'CREATE' OR $event = 'UPDATE' THEN {
    IF ($after.is_super_admin OR $after.is_admin) AND $after.is_default {
        THROW 'Forbidden.';
    };
};
DEFINE EVENT enforce_one_default_role ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    IF $after.is_default {
        LET $existing_default = (SELECT * FROM role WHERE is_default = true);
        IF array::len($existing_default) > 1 {
            THROW 'A default role already exists. Deactivate it first.';
        };
    };
};
DEFINE FIELD is_admin ON TABLE role VALUE IF $value IS NOT NONE { <bool>$value } ELSE { false };
DEFINE FIELD is_super_admin ON TABLE role TYPE bool DEFAULT false;
DEFINE EVENT enforce_one_super_admin_role ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    IF $after.is_super_admin {
        LET $existing_default = (SELECT * FROM role WHERE is_super_admin = true);
        IF array::len($existing_default) > 1 {
            THROW 'A super admin role already exists.';
        };
    };
};
DEFINE EVENT enforce_either_admin_or_super_admin ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    IF $after.is_super_admin AND $after.is_admin {
        THROW 'Has to be either admin or super_admin.';
    };
};
DEFINE INDEX roleNameIndex ON TABLE role COLUMNS role_name UNIQUE;
DEFINE FIELD OVERWRITE created_by ON TABLE role TYPE record<user>;

DEFINE FIELD created_at ON TABLE role TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE role TYPE datetime
  VALUE time::now();


-- A schema-full permission table.
DEFINE TABLE permission SCHEMAFULL TYPE NORMAL;
DEFINE FIELD name ON TABLE permission TYPE string
      ASSERT string::matches($value, "^(read|write|delete|assign|grant|revoke):[A-Za-z0-9_]+$");
DEFINE EVENT enforce_either_admin_or_super_admin ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
      IF $after.is_super_admin AND $after.is_admin {
          THROW 'Has to be either admin or super_admin.';
      };
  };
DEFINE FIELD OVERWRITE resource ON TABLE permission TYPE record<resource>;
DEFINE FIELD OVERWRITE created_by ON TABLE permission TYPE record<user>;
DEFINE INDEX permissionNameIndex on TABLE permission COLUMNS name UNIQUE;
DEFINE FIELD is_admin ON TABLE permission VALUE IF $value IS NOT NONE { <bool>$value } ELSE { false };
DEFINE FIELD is_super_admin ON TABLE permission VALUE IF $value IS NOT NONE { <bool>$value } ELSE { false };
DEFINE FIELD created_at ON TABLE permission TYPE datetime
    DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE permission TYPE datetime
    VALUE time::now();

-- Relationship between permissions and roles
DEFINE TABLE granted SCHEMAFULL TYPE RELATION IN role OUT permission;
DEFINE INDEX rolePermissionIndex ON TABLE granted COLUMNS in, out UNIQUE;
DEFINE FIELD created_at ON TABLE granted TYPE datetime
    DEFAULT time::now() READONLY;


-- Relationship between user and roles
DEFINE TABLE assigned SCHEMAFULL TYPE RELATION IN user OUT role;
DEFINE FIELD is_default ON TABLE assigned TYPE bool DEFAULT false;
DEFINE EVENT enforce_one_default_assigned_role ON TABLE assigned WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    IF $after.is_default {
    LET $existing_default = (SELECT * FROM assigned WHERE is_default = true AND in = $after.in);
        IF array::len($existing_default) > 1 {
            THROW 'You already have a default role. Deactivate it first.';
        };
    };
};
DEFINE EVENT enforce_one_super_admin_role ON TABLE assigned WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    LET $existing_superadmin = (SELECT <-assigned as super_admin_roles FROM role WHERE is_super_admin = true)[0]["super_admin_roles"];
    IF array::len($existing_superadmin) > 1 {
        THROW 'Super admin role already assigned. Unauthorized unless delegated by an existing super admin.';
    };
};
DEFINE INDEX userRoleIndex ON TABLE assigned
COLUMNS in, out UNIQUE;
DEFINE FIELD created_at ON TABLE assigned TYPE datetime
    DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE assigned TYPE datetime
    VALUE time::now();

-- A schema-full resource table
DEFINE TABLE resource SCHEMAFULL TYPE NORMAL;
DEFINE FIELD name ON TABLE resource TYPE string VALUE string::lowercase($value)
    ASSERT string::matches($value, "^[A-Za-z0-9_]+$");
DEFINE INDEX resourceNameIndex ON TABLE resource COLUMNS name, created_by UNIQUE;
DEFINE FIELD OVERWRITE created_by ON TABLE resource TYPE record<user>;
DEFINE FIELD created_at ON TABLE resource TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE resource TYPE datetime
  VALUE time::now();

-- A schema-full organization table
DEFINE TABLE organization SCHEMAFULL TYPE NORMAL;
DEFINE FIELD org_name ON TABLE organization TYPE string VALUE string::uppercase($value)
    ASSERT string::matches($value, "^[A-Za-z0-9_]+$");
DEFINE INDEX orgNameIndex ON TABLE organization COLUMNS org_name, created_by UNIQUE;
DEFINE FIELD OVERWRITE created_by ON TABLE organization TYPE record<user>;
DEFINE FIELD created_at ON TABLE organization TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE organization TYPE datetime
  VALUE time::now();

-- A schema-full department table
DEFINE TABLE department SCHEMAFULL TYPE NORMAL;
DEFINE FIELD dep_name ON TABLE department TYPE string VALUE string::uppercase($value)
    ASSERT string::matches($value, "^[A-Za-z0-9_]+$");
DEFINE INDEX depNameIndex ON TABLE department COLUMNS dep_name, created_by UNIQUE;
DEFINE FIELD OVERWRITE created_by ON TABLE department TYPE record<user>;
DEFINE FIELD created_at ON TABLE department TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE department TYPE datetime
  VALUE time::now();


-- A schema-full relation table for departments
DEFINE TABLE is_under SCHEMAFULL TYPE RELATION IN resource | role | department OUT department | organization;
DEFINE INDEX isUnderIndex ON TABLE is_under
COLUMNS in, out UNIQUE;
DEFINE FIELD created_at ON TABLE is_under TYPE datetime
  DEFAULT time::now() READONLY;


-- Function to check if user has a role, if not, assign a default role using edge relationship
DEFINE FUNCTION fn::assign_default_role($user_id: record) {
  LET $results = (SELECT ->assigned AS roles FROM ONLY $user_id);

  IF array::len($results.roles) == 0 {
    LET $default_role = (SELECT VALUE id FROM ONLY role WHERE is_default = true LIMIT 1);

    RELATE $user_id->assigned->$default_role CONTENT {
      is_default: true
    };
  };
};

-- Migrations
-- UPDATE assigned SET is_default = false WHERE is_default IS NONE;
-- UPDATE role SET is_default = false WHERE is_default IS NONE;
-- UPDATE role SET is_admin = false, is_super_admin = false WHERE is_admin IS NONE OR is_super_admin IS NONE;
-- UPDATE organization SET created_by = user:8beo2dgkz7yoy26d04rt WHERE created_by IS NONE;
-- UPDATE department SET created_by = user:8beo2dgkz7yoy26d04rt WHERE created_by IS NONE;
