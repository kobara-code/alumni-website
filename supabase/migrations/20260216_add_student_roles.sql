-- Add student role fields to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS student_role text;

-- student_role can be: '회장', '총무', or NULL for regular students
