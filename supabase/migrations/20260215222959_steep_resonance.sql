/*
  # 금고중앙동문회 데이터베이스 스키마

  1. New Tables
    - `users` - 사용자 정보 (동문, 관리자, 재학생)
    - `notices` - 공지사항
    - `comments` - 공지사항 댓글
    - `finances` - 회계 내역
    - `settings` - 시스템 설정
    - `events` - 행사 참석 정보
    - `change_requests` - 정보 변경 요청
    - `activity_logs` - 활동 로그
    - `gallery` - 사진 갤러리

  2. Security
    - Enable RLS on all tables
    - Add policies for authenticated users
*/

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    password text NOT NULL,
    graduation_year integer,
    phone text,
    work_address text,
    home_address text,
    is_admin boolean DEFAULT false,
    is_student boolean DEFAULT false,
    phone_public boolean DEFAULT true,
    work_address_public boolean DEFAULT true,
    home_address_public boolean DEFAULT true,
    created_at timestamptz DEFAULT now()
);

-- Notices table
CREATE TABLE IF NOT EXISTS notices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    content text NOT NULL,
    images text,
    created_at timestamptz DEFAULT now(),
    author text NOT NULL
);

-- Comments table
CREATE TABLE IF NOT EXISTS comments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    notice_id uuid REFERENCES notices(id) ON DELETE CASCADE,
    author text NOT NULL,
    author_year integer,
    content text NOT NULL,
    created_at timestamptz DEFAULT now()
);

-- Finances table
CREATE TABLE IF NOT EXISTS finances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type text NOT NULL CHECK (type IN ('income', 'expense')),
    description text NOT NULL,
    amount integer NOT NULL,
    date timestamptz DEFAULT now(),
    created_by text NOT NULL
);

-- Settings table
CREATE TABLE IF NOT EXISTS settings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key text UNIQUE NOT NULL,
    value text NOT NULL
);

-- Events table
CREATE TABLE IF NOT EXISTS events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    attendance_status text DEFAULT '무응답',
    notes text,
    updated_by text,
    updated_at timestamptz DEFAULT now()
);

-- Change requests table
CREATE TABLE IF NOT EXISTS change_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    field_name text NOT NULL,
    old_value text,
    new_value text,
    requested_by text,
    status text DEFAULT 'pending',
    created_at timestamptz DEFAULT now(),
    processed_at timestamptz
);

-- Activity logs table
CREATE TABLE IF NOT EXISTS activity_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action text NOT NULL,
    target_user text,
    details text,
    performed_by text,
    created_at timestamptz DEFAULT now()
);

-- Gallery table
CREATE TABLE IF NOT EXISTS gallery (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    filename text NOT NULL,
    original_name text NOT NULL,
    uploaded_by text,
    created_at timestamptz DEFAULT now()
);

-- Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE finances ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gallery ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can read all users" ON users FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can update own profile" ON users FOR UPDATE TO authenticated USING (auth.uid()::text = id::text);
CREATE POLICY "Admins can manage users" ON users FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);

CREATE POLICY "Users can read notices" ON notices FOR SELECT TO authenticated USING (true);
CREATE POLICY "Admins can manage notices" ON notices FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);

CREATE POLICY "Users can read comments" ON comments FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users can add comments" ON comments FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Users can update own comments" ON comments FOR UPDATE TO authenticated USING (
    author = (SELECT name FROM users WHERE id::text = auth.uid()::text)
);

CREATE POLICY "Users can read finances" ON finances FOR SELECT TO authenticated USING (true);
CREATE POLICY "Admins can manage finances" ON finances FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);

CREATE POLICY "Users can read settings" ON settings FOR SELECT TO authenticated USING (true);
CREATE POLICY "Admins can manage settings" ON settings FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);

CREATE POLICY "Students and admins can read events" ON events FOR SELECT TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND (is_admin = true OR is_student = true))
);
CREATE POLICY "Students and admins can manage events" ON events FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND (is_admin = true OR is_student = true))
);

CREATE POLICY "Admins can read change requests" ON change_requests FOR SELECT TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);
CREATE POLICY "Students can create change requests" ON change_requests FOR INSERT TO authenticated WITH CHECK (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_student = true)
);

CREATE POLICY "Admins can read activity logs" ON activity_logs FOR SELECT TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);
CREATE POLICY "System can insert activity logs" ON activity_logs FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Users can read gallery" ON gallery FOR SELECT TO authenticated USING (true);
CREATE POLICY "Admins can manage gallery" ON gallery FOR ALL TO authenticated USING (
    EXISTS (SELECT 1 FROM users WHERE id::text = auth.uid()::text AND is_admin = true)
);

-- Helper functions
CREATE OR REPLACE FUNCTION sum_finances_by_type(finance_type text)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
AS $$
    SELECT COALESCE(SUM(amount), 0) FROM finances WHERE type = finance_type;
$$;