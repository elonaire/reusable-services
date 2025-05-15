-- Enable GraphQL
-- DEFINE CONFIG GRAPHQL AUTO;

-- A schema-full user table.
DEFINE TABLE OVERWRITE user SCHEMAFULL;
-- define some fields.
DEFINE FIELD user_name ON TABLE user TYPE option<string>;
DEFINE INDEX userNameIndex ON TABLE user COLUMNS user_name UNIQUE;
DEFINE FIELD first_name ON TABLE user TYPE option<string>;
DEFINE FIELD middle_name ON TABLE user TYPE option<string>;
DEFINE FIELD last_name ON TABLE user TYPE option<string>;
DEFINE FIELD gender ON TABLE user TYPE option<string>
-- Allow only these values in the array
  ASSERT $value INSIDE ['Male', 'Female', 'Other', None];
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
DEFINE FIELD OVERWRITE password ON TABLE user TYPE option<string>
  DEFAULT None;
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
  ASSERT $value INSIDE ['Google', 'Github', None];
DEFINE FIELD oauth_user_id ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD address ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD profile_picture ON TABLE user TYPE option<string>
  ASSERT string::is::url($value)
  DEFAULT None;
DEFINE FIELD bio ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD website ON TABLE user TYPE option<string>
  ASSERT string::is::url($value)
  DEFAULT None;
DEFINE FIELD created_at ON TABLE user TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE user TYPE datetime
  VALUE time::now();

-- A schema-full role table.
DEFINE TABLE role SCHEMAFULL;
-- define some fields.
DEFINE FIELD role_name ON TABLE role TYPE string VALUE string::uppercase($value);
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
DEFINE FIELD is_admin ON TABLE role TYPE bool DEFAULT false;
DEFINE FIELD is_super_admin ON TABLE role TYPE bool DEFAULT false;
DEFINE EVENT enforce_one_super_admin_role ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
    IF $after.is_super_admin {
        LET $existing_default = (SELECT * FROM role WHERE is_super_admin = true);
        IF array::len($existing_default) > 1 {
            THROW 'A super admin role already exists.';
        };
    };
};
DEFINE INDEX roleNameIndex ON TABLE role COLUMNS role_name UNIQUE;
DEFINE FIELD OVERWRITE created_by ON TABLE role TYPE record<user>;
DEFINE FIELD admin_permissions ON TABLE role TYPE option<array<string>>
  ASSERT $value ALLINSIDE ['CreateOrganization', 'CreateDepartment', 'CreateRole', 'AssignRole'];
DEFINE EVENT OVERWRITE evaluate_admin_permissions ON TABLE role WHEN $event = 'CREATE' OR $event = 'UPDATE' THEN {
  IF (!$after.is_super_admin AND $after.admin_permissions IS NOT NONE AND $after.admin_permissions CONTAINS "CreateOrganization") OR (!$after.is_super_admin AND !$after.is_admin AND $after.admin_permissions IS NOT NONE AND $after.admin_permissions CONTAINSANY ['CreateDepartment', 'CreateRole', 'AssignRole']) {
    THROW 'Not enough permissions.';
  };
};

DEFINE FIELD created_at ON TABLE role TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE role TYPE datetime
  VALUE time::now();


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

-- A schema-full organization table
DEFINE TABLE organization SCHEMAFULL TYPE RELATION IN role OUT role;
DEFINE FIELD org_name ON TABLE organization TYPE string;
DEFINE INDEX orgNameIndex ON TABLE organization COLUMNS org_name UNIQUE;
DEFINE FIELD created_at ON TABLE organization TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE organization TYPE datetime
  VALUE time::now();

-- A schema-full department table
DEFINE TABLE department SCHEMAFULL TYPE NORMAL;
DEFINE FIELD dep_name ON TABLE department TYPE string;
DEFINE INDEX depNameIndex ON TABLE department COLUMNS org_name UNIQUE;
DEFINE FIELD created_at ON TABLE department TYPE datetime
  DEFAULT time::now() READONLY;
DEFINE FIELD updated_at ON TABLE department TYPE datetime
  VALUE time::now();


-- A schema-full relation table for departments
DEFINE TABLE OVERWRITE is_under SCHEMAFULL TYPE RELATION IN department OUT department | organization;


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
