from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
from datetime import datetime
import os
import hashlib
import secrets
import re

def format_phone(phone):
    if not phone:
        return '-'
    # 숫자만 추출
    digits = re.sub(r'\D', '', phone)
    if len(digits) == 11:
        return f'{digits[:3]}-{digits[3:7]}-{digits[7:]}'
    elif len(digits) == 10:
        return f'{digits[:3]}-{digits[3:6]}-{digits[6:]}'
    return phone

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Jinja2 필터 등록
app.jinja_env.filters['format_phone'] = format_phone

def hash_sensitive_data(data):
    if not data:
        return None
    return hashlib.sha256(data.encode()).hexdigest()[:8] + "***"

def init_db():
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        graduation_year INTEGER,
        phone TEXT,
        work_address TEXT,
        home_address TEXT,
        is_admin INTEGER DEFAULT 0,
        is_student INTEGER DEFAULT 0,
        phone_public INTEGER DEFAULT 1,
        work_address_public INTEGER DEFAULT 1,
        home_address_public INTEGER DEFAULT 1
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS notices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        images TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        author TEXT NOT NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        notice_id INTEGER,
        author TEXT NOT NULL,
        author_year INTEGER,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (notice_id) REFERENCES notices (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS finances (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        description TEXT NOT NULL,
        amount INTEGER NOT NULL,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT NOT NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        attendance_status TEXT DEFAULT '무응답',
        notes TEXT,
        updated_by TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS change_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        field_name TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT,
        requested_by TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        processed_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        target_user TEXT,
        details TEXT,
        performed_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS gallery (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_name TEXT NOT NULL,
        uploaded_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 기본 설정값 추가
    settings = [
        ('finance_public', '1'),
        ('finance_details_public', '1'),
        ('bank_info_public', '1'),
        ('bank_name', '국민은행'),
        ('account_number', '123-456-789012'),
        ('account_holder', '금호중앙동문회'),
        ('site_name', '금호중앙동문회')
    ]
    
    for key, value in settings:
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
    
    # 기본 관리자 계정 생성
    c.execute("SELECT * FROM users WHERE name = '관리자'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin1234')
        c.execute("INSERT INTO users (name, password, is_admin) VALUES (?, ?, 1)", 
                 ('관리자', admin_password))
    
    conn.commit()
    conn.close()

def log_activity(action, target_user=None, details=None):
    try:
        conn = sqlite3.connect('alumni.db')
        c = conn.cursor()
        c.execute("INSERT INTO activity_logs (action, target_user, details, performed_by) VALUES (?, ?, ?, ?)",
                 (action, target_user, details, session.get('user_name', 'System')))
        conn.commit()
        conn.close()
    except:
        pass

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = 'site_name'")
    result = c.fetchone()
    site_name = result[0] if result else '금호중앙동문회'
    
    # 갤러리 이미지 가져오기
    c.execute("SELECT * FROM gallery ORDER BY created_at DESC LIMIT 5")
    gallery_images = c.fetchall()
    
    conn.close()
    
    return render_template('index.html', site_name=site_name, gallery_images=gallery_images)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        
        conn = sqlite3.connect('alumni.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE name = ?", (name,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['user_year'] = user[3]
            session['is_admin'] = user[7]
            session['is_student'] = user[8]
            log_activity('로그인', user[1])
            return redirect(url_for('index'))
        else:
            flash('이름 또는 비밀번호가 잘못되었습니다.')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    log_activity('로그아웃', session.get('user_name'))
    session.clear()
    return redirect(url_for('login'))

@app.route('/directory')
def directory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    search = request.args.get('search', '')
    year_filter = request.args.get('year', '')
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    query = "SELECT * FROM users WHERE name != '관리자'"
    params = []
    
    if search:
        query += " AND name LIKE ?"
        params.append(f'%{search}%')
    
    if year_filter:
        query += " AND graduation_year = ?"
        params.append(year_filter)
    
    query += " ORDER BY graduation_year DESC, name"
    
    c.execute(query, params)
    users = c.fetchall()
    
    c.execute("SELECT DISTINCT graduation_year FROM users WHERE graduation_year IS NOT NULL ORDER BY graduation_year DESC")
    years = [row[0] for row in c.fetchall()]
    
    conn.close()
    
    is_admin_or_student = session.get('is_admin') or session.get('is_student')
    
    return render_template('directory.html', users=users, years=years, 
                         search=search, year_filter=year_filter, 
                         is_admin_or_student=is_admin_or_student)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    phone = request.form['phone']
    work_address = request.form['work_address']
    home_address = request.form['home_address']
    phone_public = 1 if 'phone_public' in request.form else 0
    work_address_public = 1 if 'work_address_public' in request.form else 0
    home_address_public = 1 if 'home_address_public' in request.form else 0
    new_password = request.form.get('new_password')
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    if new_password:
        hashed_password = generate_password_hash(new_password)
        c.execute("UPDATE users SET phone = ?, work_address = ?, home_address = ?, phone_public = ?, work_address_public = ?, home_address_public = ?, password = ? WHERE id = ?",
                 (phone, work_address, home_address, phone_public, work_address_public, home_address_public, hashed_password, session['user_id']))
        log_activity('비밀번호 변경', session['user_name'])
    else:
        c.execute("UPDATE users SET phone = ?, work_address = ?, home_address = ?, phone_public = ?, work_address_public = ?, home_address_public = ? WHERE id = ?",
                 (phone, work_address, home_address, phone_public, work_address_public, home_address_public, session['user_id']))
    
    log_activity('프로필 수정', session['user_name'])
    conn.commit()
    conn.close()
    
    flash('프로필이 업데이트되었습니다.')
    return redirect(url_for('profile'))

@app.route('/notices')
def notices():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM notices ORDER BY created_at DESC")
    notices = c.fetchall()
    conn.close()
    
    return render_template('notices.html', notices=notices)

@app.route('/notice/<int:notice_id>')
def notice_detail(notice_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM notices WHERE id = ?", (notice_id,))
    notice = c.fetchone()
    
    c.execute("SELECT * FROM comments WHERE notice_id = ? ORDER BY created_at", (notice_id,))
    comments = c.fetchall()
    
    conn.close()
    
    return render_template('notice_detail.html', notice=notice, comments=comments)

@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    notice_id = request.form['notice_id']
    content = request.form['content']
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    author_name = session['user_name']
    if session['user_name'] != '관리자' and session.get('user_year'):
        author_name = f"{session.get('user_year')}기 {session['user_name']}"
    
    c.execute("INSERT INTO comments (notice_id, author, content) VALUES (?, ?, ?)",
             (notice_id, author_name, content))
    conn.commit()
    conn.close()
    
    return redirect(url_for('notice_detail', notice_id=notice_id))

@app.route('/finances')
def finances():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute("SELECT value FROM settings WHERE key = 'finance_public'")
    finance_public = c.fetchone()[0] == '1'
    
    c.execute("SELECT value FROM settings WHERE key = 'finance_details_public'")
    finance_details_public = c.fetchone()[0] == '1'
    
    c.execute("SELECT value FROM settings WHERE key = 'bank_info_public'")
    bank_info_public = c.fetchone()[0] == '1'
    
    if not finance_public and not session.get('is_admin'):
        flash('회계 정보는 현재 비공개 상태입니다.')
        return redirect(url_for('index'))
    
    finances = []
    if finance_details_public or session.get('is_admin'):
        c.execute("SELECT * FROM finances ORDER BY date DESC")
        finances = c.fetchall()
    
    c.execute("SELECT SUM(amount) FROM finances WHERE type = 'income'")
    total_income = c.fetchone()[0] or 0
    
    c.execute("SELECT SUM(amount) FROM finances WHERE type = 'expense'")
    total_expense = c.fetchone()[0] or 0
    
    bank_info = {}
    if bank_info_public or session.get('is_admin'):
        c.execute("SELECT key, value FROM settings WHERE key IN ('bank_name', 'account_number', 'account_holder')")
        bank_info = dict(c.fetchall())
    
    conn.close()
    
    balance = total_income - total_expense
    
    return render_template('finances.html', finances=finances, 
                         total_income=total_income, total_expense=total_expense, balance=balance,
                         bank_info=bank_info, finance_public=finance_public,
                         finance_details_public=finance_details_public,
                         bank_info_public=bank_info_public)

@app.route('/events')
def events():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('is_student')):
        flash('접근 권한이 없습니다.')
        return redirect(url_for('index'))
    
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    query = """SELECT u.id, u.name, u.graduation_year, u.phone, 
                      COALESCE(u.work_address, '') as work_address, 
                      COALESCE(u.home_address, '') as home_address,
                      COALESCE(e.attendance_status, '무응답') as status, 
                      COALESCE(e.notes, '') as notes
               FROM users u 
               LEFT JOIN events e ON u.id = e.user_id 
               WHERE u.name != '관리자'"""
    
    params = []
    if status_filter:
        query += " AND COALESCE(e.attendance_status, '무응답') = ?"
        params.append(status_filter)
    
    if search:
        query += " AND u.name LIKE ?"
        params.append(f'%{search}%')
    
    query += " ORDER BY u.graduation_year DESC, u.name"
    
    c.execute(query, params)
    users_events = c.fetchall()
    
    # 상태별 인원 수 계산
    c.execute("""SELECT COALESCE(e.attendance_status, '무응답') as status, COUNT(*) 
                 FROM users u 
                 LEFT JOIN events e ON u.id = e.user_id 
                 WHERE u.name != '관리자' 
                 GROUP BY COALESCE(e.attendance_status, '무응답')""")
    status_counts = dict(c.fetchall())
    
    conn.close()
    
    return render_template('events.html', users_events=users_events, status_counts=status_counts, 
                         status_filter=status_filter, search=search)

@app.route('/update_attendance', methods=['POST'])
def update_attendance():
    if 'user_id' not in session or not session.get('is_student'):
        return jsonify({'success': False})
    
    user_id = request.form['user_id']
    status = request.form['status']
    notes = request.form.get('notes', '')
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))
    c.execute("INSERT INTO events (user_id, attendance_status, notes, updated_by) VALUES (?, ?, ?, ?)",
             (user_id, status, notes, session['user_name']))
    
    c.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user_name = c.fetchone()[0]
    
    log_activity('참석상태 변경', user_name, f'{status} - {notes}')
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/request_change', methods=['POST'])
def request_change():
    if 'user_id' not in session or not session.get('is_student'):
        return jsonify({'success': False})
    
    user_id = request.form['user_id']
    field_name = request.form['field_name']
    new_value = request.form['new_value']
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute(f"SELECT {field_name} FROM users WHERE id = ?", (user_id,))
    old_value = c.fetchone()[0]
    
    c.execute("INSERT INTO change_requests (user_id, field_name, old_value, new_value, requested_by) VALUES (?, ?, ?, ?, ?)",
             (user_id, field_name, old_value, new_value, session['user_name']))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('관리자 권한이 필요합니다.')
        return redirect(url_for('index'))
    
    return render_template('admin.html')

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY graduation_year DESC, name")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    name = request.form['name']
    graduation_year = request.form['graduation_year']
    phone = request.form['phone']
    work_address = request.form['work_address']
    home_address = request.form['home_address']
    is_student = 1 if 'is_student' in request.form else 0
    password = generate_password_hash(f"{name}1234")
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (name, password, graduation_year, phone, work_address, home_address, is_student) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (name, password, graduation_year, phone, work_address, home_address, is_student))
    
    user_id = c.lastrowid
    c.execute("INSERT INTO events (user_id) VALUES (?)", (user_id,))
    
    log_activity('동문 추가', name, f'{graduation_year}기')
    
    conn.commit()
    conn.close()
    
    flash(f'{name} 동문이 추가되었습니다. 초기 비밀번호: {name}1234')
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    name = request.form['name']
    graduation_year = request.form['graduation_year']
    phone = request.form['phone']
    work_address = request.form['work_address']
    home_address = request.form['home_address']
    is_student = 1 if 'is_student' in request.form else 0
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, graduation_year = ?, phone = ?, work_address = ?, home_address = ?, is_student = ? WHERE id = ?",
             (name, graduation_year, phone, work_address, home_address, is_student, user_id))
    
    log_activity('동문 정보 수정', name)
    
    conn.commit()
    conn.close()
    
    flash(f'{name} 동문 정보가 수정되었습니다.')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if user and user[0] != '관리자':
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        c.execute("DELETE FROM events WHERE user_id = ?", (user_id,))
        log_activity('동문 삭제', user[0])
        conn.commit()
        flash(f'{user[0]} 동문이 삭제되었습니다.')
    
    conn.close()
    return redirect(url_for('admin_users'))

@app.route('/admin/notices')
def admin_notices():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM notices ORDER BY created_at DESC")
    notices = c.fetchall()
    conn.close()
    
    return render_template('admin_notices.html', notices=notices)

@app.route('/admin/add_notice', methods=['POST'])
def add_notice():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    title = request.form['title']
    content = request.form['content']
    image_paths = []
    
    if 'images' in request.files:
        files = request.files.getlist('images')
        for i, file in enumerate(files):
            if file and file.filename:
                filename = secure_filename(file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{i}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_paths.append(filename)
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("INSERT INTO notices (title, content, images, author) VALUES (?, ?, ?, ?)",
             (title, content, ','.join(image_paths), session['user_name']))
    
    log_activity('공지사항 작성', None, title)
    
    conn.commit()
    conn.close()
    
    flash('공지사항이 등록되었습니다.')
    return redirect(url_for('admin_notices'))

@app.route('/admin/edit_notice/<int:notice_id>', methods=['POST'])
def edit_notice(notice_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    title = request.form['title']
    content = request.form['content']
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("UPDATE notices SET title = ?, content = ? WHERE id = ?",
             (title, content, notice_id))
    
    log_activity('공지사항 수정', None, title)
    
    conn.commit()
    conn.close()
    
    flash('공지사항이 수정되었습니다.')
    return redirect(url_for('admin_notices'))

@app.route('/admin/delete_notice/<int:notice_id>', methods=['POST'])
def delete_notice(notice_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT title FROM notices WHERE id = ?", (notice_id,))
    notice = c.fetchone()
    
    if notice:
        c.execute("DELETE FROM notices WHERE id = ?", (notice_id,))
        c.execute("DELETE FROM comments WHERE notice_id = ?", (notice_id,))
        log_activity('공지사항 삭제', None, notice[0])
        conn.commit()
        flash('공지사항이 삭제되었습니다.')
    
    conn.close()
    return redirect(url_for('admin_notices'))

@app.route('/edit_comment/<int:comment_id>', methods=['POST'])
def edit_comment(comment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    content = request.form['content']
    notice_id = request.form['notice_id']
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    author_name = session['user_name']
    if session['user_name'] != '관리자' and session.get('user_year'):
        author_name = f"{session.get('user_year')}기 {session['user_name']}"
    
    c.execute("UPDATE comments SET content = ? WHERE id = ? AND author = ?",
             (content, comment_id, author_name))
    conn.commit()
    conn.close()
    
    return redirect(url_for('notice_detail', notice_id=notice_id))

@app.route('/admin/add_finance', methods=['POST'])
def add_finance():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    type = request.form['type']
    description = request.form['description']
    amount = int(request.form['amount'])
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("INSERT INTO finances (type, description, amount, created_by) VALUES (?, ?, ?, ?)",
             (type, description, amount, session['user_name']))
    
    log_activity('회계내역 추가', None, f'{type}: {description} {amount}원')
    
    conn.commit()
    conn.close()
    
    flash('회계 내역이 추가되었습니다.')
    return redirect(url_for('finances'))

@app.route('/admin/edit_finance/<int:finance_id>', methods=['POST'])
def edit_finance(finance_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    type = request.form['type']
    description = request.form['description']
    amount = int(request.form['amount'])
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("UPDATE finances SET type = ?, description = ?, amount = ? WHERE id = ?",
             (type, description, amount, finance_id))
    
    log_activity('회계내역 수정', None, f'{type}: {description} {amount}원')
    
    conn.commit()
    conn.close()
    
    flash('회계 내역이 수정되었습니다.')
    return redirect(url_for('finances'))

@app.route('/admin/delete_finance/<int:finance_id>', methods=['POST'])
def delete_finance(finance_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT description FROM finances WHERE id = ?", (finance_id,))
    finance = c.fetchone()
    
    if finance:
        c.execute("DELETE FROM finances WHERE id = ?", (finance_id,))
        log_activity('회계내역 삭제', None, finance[0])
        conn.commit()
        flash('회계 내역이 삭제되었습니다.')
    
    conn.close()
    return redirect(url_for('finances'))

@app.route('/admin/settings')
def admin_settings():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT key, value FROM settings")
    settings = dict(c.fetchall())
    
    c.execute("SELECT * FROM change_requests WHERE status = 'pending' ORDER BY created_at DESC")
    change_requests = c.fetchall()
    
    conn.close()
    
    return render_template('admin_settings.html', settings=settings, change_requests=change_requests)

@app.route('/admin/update_settings', methods=['POST'])
def update_settings():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    settings_to_update = [
        ('finance_public', '1' if 'finance_public' in request.form else '0'),
        ('finance_details_public', '1' if 'finance_details_public' in request.form else '0'),
        ('bank_info_public', '1' if 'bank_info_public' in request.form else '0'),
        ('bank_name', request.form['bank_name']),
        ('account_number', request.form['account_number']),
        ('account_holder', request.form['account_holder'])
    ]
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    for key, value in settings_to_update:
        c.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    
    log_activity('시스템 설정 변경')
    
    conn.commit()
    conn.close()
    
    flash('설정이 업데이트되었습니다.')
    return redirect(url_for('admin_settings'))

@app.route('/admin/approve_change/<int:request_id>', methods=['POST'])
def approve_change(request_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    
    c.execute("SELECT * FROM change_requests WHERE id = ?", (request_id,))
    change_req = c.fetchone()
    
    if change_req:
        c.execute(f"UPDATE users SET {change_req[2]} = ? WHERE id = ?", (change_req[4], change_req[1]))
        c.execute("UPDATE change_requests SET status = 'approved', processed_at = CURRENT_TIMESTAMP WHERE id = ?", (request_id,))
        
        c.execute("SELECT name FROM users WHERE id = ?", (change_req[1],))
        user_name = c.fetchone()[0]
        
        log_activity('변경요청 승인', user_name, f'{change_req[2]}: {change_req[3]} → {change_req[4]}')
        
        conn.commit()
        flash('변경 요청이 승인되었습니다.')
    
    conn.close()
    return redirect(url_for('admin_settings'))

@app.route('/admin/logs')
def admin_logs():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    
    return render_template('admin_logs.html', logs=logs)

@app.route('/admin/gallery')
def admin_gallery():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('alumni.db')
    c = conn.cursor()
    c.execute("SELECT * FROM gallery ORDER BY created_at DESC")
    images = c.fetchall()
    conn.close()
    
    return render_template('admin_gallery.html', images=images)

@app.route('/admin/upload_image', methods=['POST'])
def upload_image():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    if 'images' in request.files:
        files = request.files.getlist('images')
        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                conn = sqlite3.connect('alumni.db')
                c = conn.cursor()
                c.execute("INSERT INTO gallery (filename, original_name, uploaded_by) VALUES (?, ?, ?)",
                         (filename, file.filename, session['user_name']))
                conn.commit()
                conn.close()
        
        flash('이미지가 업로드되었습니다.')
    
    return redirect(url_for('admin_gallery'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
