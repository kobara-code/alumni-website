-- Reset all user passwords to '1234' (except admin)
-- Note: The password hash is generated using werkzeug.security.generate_password_hash('1234')
-- You need to run this command in Python to get the hash:
-- python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('1234'))"

-- Then update this SQL with the generated hash
-- Example: UPDATE users SET password = 'pbkdf2:sha256:600000$...' WHERE name != '관리자' AND is_admin = false;

-- IMPORTANT: Run the Python command above to generate a fresh hash, then execute:
-- UPDATE users SET password = '<generated_hash>' WHERE name != '관리자' AND is_admin = false;
