-- A schema-full user table.
DEFINE TABLE user SCHEMAFULL;

-- define some fields.
DEFINE FIELD user_name ON TABLE user TYPE string;
DEFINE INDEX userNameIndex ON TABLE user COLUMNS user_name UNIQUE;
DEFINE FIELD first_name ON TABLE user TYPE string;
DEFINE FIELD middle_name ON TABLE user TYPE string;
DEFINE FIELD last_name ON TABLE user TYPE string;
DEFINE FIELD gender ON TABLE user TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["Male", "Female", "Other"];
DEFINE FIELD dob ON TABLE user VALUE <datetime>$value;
DEFINE FIELD email ON TABLE user TYPE string
  ASSERT string::is::email($value);
DEFINE INDEX userEmailIndex ON TABLE user COLUMNS email UNIQUE;
DEFINE FIELD country ON TABLE user TYPE string;
DEFINE FIELD phone ON TABLE user TYPE string
  ASSERT string::len($value) == 10;
DEFINE INDEX userPhoneIndex ON TABLE user COLUMNS phone UNIQUE;
DEFINE FIELD password ON TABLE user TYPE string;
DEFINE EVENT user_created ON TABLE user WHEN $event = "CREATE" THEN (
    -- add default role to user
    fn::assign_default_role($after.id)
);
DEFINE FIELD status ON TABLE user TYPE string
  DEFAULT "Inactive"
-- Allow only these values in the array
  ASSERT $value INSIDE ["Active", "Inactive", "Suspended", "Deleted"];
DEFINE FIELD oauth_client ON TABLE user TYPE option<string>
-- Allow only these values in the array
  ASSERT $value INSIDE ["Google", "Github", None];
DEFINE FIELD address ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD profile_picture ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD bio ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD website ON TABLE user TYPE option<string>
  DEFAULT None;
DEFINE FIELD created_at ON TABLE user TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE user TYPE datetime
  VALUE time::now();

-- A schema-full role table.
DEFINE TABLE role SCHEMAFULL;
-- define some fields.
DEFINE FIELD role_name ON TABLE role TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["Admin", "User", "Guest"];
DEFINE INDEX roleNameIndex ON TABLE role COLUMNS role_name UNIQUE;
DEFINE FIELD created_at ON TABLE role TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE role TYPE datetime
  VALUE time::now();


-- Relationship between user and roles
DEFINE TABLE has_role SCHEMAFULL;
DEFINE INDEX userRoleIndex ON TABLE has_role 
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE has_role TYPE record<user>;
DEFINE FIELD out ON TABLE has_role TYPE record<role>;

-- Function to check if user has a role, if not, assign a default role using edge relationship
DEFINE FUNCTION fn::assign_default_role($user_id: record) {
  LET $results = SELECT ->has_role FROM $user_id;
  LET $edge_name = "->has_role";

  -- LET $results = SELECT VALUE id FROM type::table("has_role") WHERE in = $user_id;
  if array::len($results[0][$edge_name]) == 0 {
    LET $default_role = SELECT * FROM role WHERE role_name = "User" LIMIT 1;
    LET $role_id = $default_role[0].id;
    RELATE $user_id->has_role->$role_id CONTENT {
      in: $user_id,
      out: $role_id
    };
  };
};
