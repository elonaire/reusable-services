-- A schema-full user_id table
DEFINE TABLE user_id SCHEMAFULL;
-- define some fields
DEFINE FIELD user_id ON TABLE user_id TYPE string;
DEFINE INDEX userIndex ON TABLE user_id COLUMNS user_id UNIQUE;

-- A schema-full professional_details table.
DEFINE TABLE professional_details SCHEMAFULL;
-- define some fields.
DEFINE FIELD occupation ON TABLE professional_details TYPE string;
DEFINE FIELD description ON TABLE professional_details TYPE string;
DEFINE FIELD start_date ON TABLE professional_details VALUE <datetime>$value;
DEFINE FIELD created_at ON TABLE professional_details TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE professional_details TYPE datetime
  VALUE time::now();

-- Relationship between user and professional_details
DEFINE TABLE has_professional_details SCHEMAFULL;
DEFINE INDEX userProfessionalDetailsIndex ON TABLE has_professional_details
COLUMNS in, out UNIQUE;
DEFINE INDEX userIdIndex ON TABLE has_professional_details
COLUMNS in;
DEFINE FIELD in ON TABLE has_professional_details TYPE record<user_id>;
DEFINE FIELD out ON TABLE has_professional_details TYPE record<professional_details>;

-- A schema-full portfolio table.
DEFINE TABLE portfolio SCHEMAFULL;
-- define some fields.
DEFINE FIELD title ON TABLE portfolio TYPE string;
DEFINE FIELD description ON TABLE portfolio TYPE string;
DEFINE FIELD start_date ON TABLE portfolio VALUE <datetime>$value;
DEFINE FIELD end_date ON TABLE portfolio VALUE
  IF $value IS NOT NONE THEN <datetime>$value
  ELSE NONE
  END;
DEFINE FIELD link ON TABLE portfolio TYPE string;
DEFINE FIELD image ON TABLE portfolio TYPE string;
DEFINE FIELD category ON TABLE portfolio TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["JavaScript", "Rust", "Database", "Cloud", "DevOps"];
DEFINE FIELD created_at ON TABLE portfolio TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE portfolio TYPE datetime
  VALUE time::now();

-- Relationship between user and portfolio
DEFINE TABLE has_portfolio SCHEMAFULL;
DEFINE INDEX userPortfolioIndex ON TABLE has_portfolio
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE has_portfolio TYPE record<user_id>;
DEFINE FIELD out ON TABLE has_portfolio TYPE record<portfolio>;

-- A schema-full resume table.
DEFINE TABLE resume SCHEMAFULL;
-- define some fields.
DEFINE FIELD section ON TABLE resume TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["Education", "Experience", "Achievements", "Skills", "Projects", "Certifications", "Volunteer", "Publications", "Languages", "Interests", "References"];
DEFINE FIELD title ON TABLE resume TYPE string;
DEFINE FIELD more_info ON TABLE resume TYPE string;
DEFINE FIELD start_date ON TABLE resume VALUE <datetime>$value;
DEFINE FIELD end_date ON TABLE resume VALUE
  IF $value IS NOT NONE THEN <datetime>$value
  ELSE NONE
  END;
DEFINE FIELD link ON TABLE resume TYPE option<string>
  DEFAULT None;
DEFINE FIELD created_at ON TABLE resume TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE resume TYPE datetime
  VALUE time::now();

-- A schema-full achievement table. Should relate to resume table
DEFINE TABLE achievement SCHEMAFULL;
-- define some fields.
DEFINE FIELD description ON TABLE achievement TYPE string;
DEFINE FIELD created_at ON TABLE achievement TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE achievement TYPE datetime
  VALUE time::now();

-- Relationship between resume and achievement
DEFINE TABLE has_achievement SCHEMAFULL;
DEFINE INDEX resumeAchievementIndex ON TABLE has_achievement
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE has_achievement TYPE record<resume>;
DEFINE FIELD out ON TABLE has_achievement TYPE record<achievement>;

-- Relationship between user and resume
DEFINE TABLE has_resume SCHEMAFULL;
DEFINE INDEX userResumeIndex ON TABLE has_resume
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE has_resume TYPE record<user_id>;
DEFINE FIELD out ON TABLE has_resume TYPE record<resume>;

-- Aschema-full service table.
DEFINE TABLE service SCHEMAFULL;
-- define some fields.
DEFINE FIELD title ON TABLE service TYPE string;
DEFINE FIELD description ON TABLE service TYPE string;
DEFINE FIELD image ON TABLE service TYPE string;
DEFINE FIELD created_at ON TABLE service TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE service TYPE datetime
  VALUE time::now();

-- Relationship between user and service
DEFINE TABLE offers_service SCHEMAFULL;
DEFINE INDEX userServiceIndex ON TABLE offers_service
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE offers_service TYPE record<user_id>;
DEFINE FIELD out ON TABLE offers_service TYPE record<service>;

-- A schema-full blog post table.
DEFINE TABLE blog_post SCHEMAFULL;
-- define some fields.
DEFINE FIELD title ON TABLE blog_post TYPE string;
DEFINE FIELD short_description ON TABLE blog_post TYPE string;
DEFINE FIELD author ON TABLE blog_post TYPE string;
DEFINE FIELD image ON TABLE blog_post TYPE string;
DEFINE FIELD category ON TABLE blog_post TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["WebDevelopment", "MobileDevelopment", "ArtificialIntelligence", "Technology", "Lifestyle"];
DEFINE FIELD link ON TABLE blog_post TYPE string;
DEFINE INDEX blogPostIndex ON TABLE blog_post COLUMNS link UNIQUE;
DEFINE FIELD status ON TABLE blog_post TYPE option<string>
-- Allow only these values in the array
  ASSERT $value INSIDE ["Draft", "Published"]
  DEFAULT "Draft";
DEFINE FIELD published_date ON TABLE blog_post VALUE 
  IF $value IS NOT NONE THEN <datetime>$value
  ELSE NONE
  END;
DEFINE FIELD created_at ON TABLE blog_post TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE blog_post TYPE datetime
  VALUE time::now();

-- Relationship between user and blog_post
DEFINE TABLE has_blog_post SCHEMAFULL;
DEFINE INDEX userBlogPostIndex ON TABLE has_blog_post
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE has_blog_post TYPE record<user_id>;
DEFINE FIELD out ON TABLE has_blog_post TYPE record<blog_post>;

-- A schema-full comment table.
DEFINE TABLE comment SCHEMAFULL;
-- define some fields.
DEFINE FIELD content ON TABLE comment TYPE string;
-- DEFINE FIELD published_date ON TABLE comment VALUE <datetime>$value;
DEFINE FIELD created_at ON TABLE comment TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE comment TYPE datetime
  VALUE time::now();

-- Relationship between user and comment
DEFINE TABLE user_has_comment SCHEMAFULL;
DEFINE INDEX userCommentIndex ON TABLE user_has_comment
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE user_has_comment TYPE record<user_id>;
DEFINE FIELD out ON TABLE user_has_comment TYPE record<comment>;

-- Relationship between blog_post and comment
DEFINE TABLE blog_post_has_comment SCHEMAFULL;
DEFINE INDEX blogPostCommentIndex ON TABLE blog_post_has_comment
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE blog_post_has_comment TYPE record<blog_post>;
DEFINE FIELD out ON TABLE blog_post_has_comment TYPE record<comment>;

-- Relationship between comment and comment
DEFINE TABLE comment_has_reply SCHEMAFULL;
DEFINE INDEX commentCommentIndex ON TABLE comment_has_reply
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE comment_has_reply TYPE record<comment>;
DEFINE FIELD out ON TABLE comment_has_reply TYPE record<comment>;

-- A schema-full reaction table.
DEFINE TABLE reaction SCHEMAFULL;
-- define some fields.
DEFINE FIELD type ON TABLE reaction TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["Like", "Dislike", "Love", "Haha", "Wow", "Sad", "Angry"];
DEFINE FIELD created_at ON TABLE reaction TYPE datetime
  DEFAULT time::now();

-- Relationship between user and reaction
DEFINE TABLE user_has_reaction SCHEMAFULL;
DEFINE INDEX userReactionIndex ON TABLE user_has_reaction
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE user_has_reaction TYPE record<user_id>;
DEFINE FIELD out ON TABLE user_has_reaction TYPE record<reaction>;

-- Relationship between blog post and reaction
DEFINE TABLE blog_post_has_reaction SCHEMAFULL;
DEFINE INDEX blogPostReactionIndex ON TABLE blog_post_has_reaction
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE blog_post_has_reaction TYPE record<blog_post>;
DEFINE FIELD out ON TABLE blog_post_has_reaction TYPE record<reaction>;

-- Relationship between comment and reaction
DEFINE TABLE comment_has_reaction SCHEMAFULL;
DEFINE INDEX commentReactionIndex ON TABLE comment_has_reaction
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE comment_has_reaction TYPE record<comment>;
DEFINE FIELD out ON TABLE comment_has_reaction TYPE record<reaction>;

-- A schema-full message table.
DEFINE TABLE message SCHEMAFULL;
-- define some fields.
DEFINE FIELD sender_name ON TABLE message TYPE string;
DEFINE FIELD sender_email ON TABLE message TYPE string;
DEFINE FIELD content ON TABLE message TYPE string;
DEFINE FIELD created_at ON TABLE message TYPE datetime
  DEFAULT time::now();

-- A schema-full file table.
DEFINE TABLE file SCHEMAFULL;
-- define some fields.
DEFINE FIELD name ON TABLE file TYPE string;
DEFINE FIELD type ON TABLE file TYPE string;
DEFINE FIELD size ON TABLE file TYPE string;
DEFINE FIELD url ON TABLE file TYPE string;
DEFINE FIELD created_at ON TABLE file TYPE datetime
  DEFAULT time::now();

-- Relationship between user and file
DEFINE TABLE user_has_file SCHEMAFULL;
DEFINE INDEX userFileIndex ON TABLE user_has_file
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE user_has_file TYPE record<user_id>;
DEFINE FIELD out ON TABLE user_has_file TYPE record<file>;

-- A schema-full notification table.
DEFINE TABLE notification SCHEMAFULL;
-- define some fields.
DEFINE FIELD content ON TABLE notification TYPE string;
DEFINE FIELD created_at ON TABLE notification TYPE datetime
  DEFAULT time::now();

-- A schema-full skill table.
DEFINE TABLE skill SCHEMAFULL;
-- define some fields.
DEFINE FIELD name ON TABLE skill TYPE string;
DEFINE FIELD image ON TABLE skill TYPE string;
DEFINE FIELD level ON TABLE skill TYPE string
-- Allow only these values in the array
  ASSERT $value INSIDE ["Beginner", "Intermediate", "Advanced", "Expert"];
DEFINE FIELD start_date ON TABLE skill VALUE <datetime>$value;
DEFINE FIELD created_at ON TABLE skill TYPE datetime
  DEFAULT time::now();
DEFINE FIELD updated_at ON TABLE skill TYPE datetime
  VALUE time::now();

-- Relationship between user and skill
DEFINE TABLE user_has_skill SCHEMAFULL;
DEFINE INDEX userSkillIndex ON TABLE user_has_skill
COLUMNS in, out UNIQUE;
DEFINE FIELD in ON TABLE user_has_skill TYPE record<user_id>;
DEFINE FIELD out ON TABLE user_has_skill TYPE record<skill>;
