import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import hashlib
import secrets
import re
import PyPDF2
import io
from supabase import create_client, Client

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
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'  # Vercel serverless는 /tmp만 쓰기 가능
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_EXTENSIONS = {'pdf', 'txt', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(file_stream):
    """PDF에서 텍스트 추출"""
    try:
        pdf_reader = PyPDF2.PdfReader(file_stream)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        return f"PDF 읽기 오류: {str(e)}"

def parse_member_data(text):
    """텍스트에서 회원 정보 파싱"""
    members = []
    lines = text.split('\n')
    
    current_member = {}
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # 이름 패턴 (한글 2-4자)
        name_match = re.search(r'([가-힣]{2,4})', line)
        
        # 기수 패턴 (숫자 + 기)
        year_match = re.search(r'(\d{1,2})기', line)
        
        # 전화번호 패턴
        phone_match = re.search(r'(01[0-9]-?\d{3,4}-?\d{4})', line)
        
        # 주소 패턴 (시/도로 시작하는 긴 텍스트)
        address_match = re.search(r'([가-힣]+[시도]\s*[가-힣\s\d-]+)', line)
        
        if name_match and year_match:
            # 새로운 회원 정보 시작
            if current_member:
                members.append(current_member)
            
            current_member = {
                'name': name_match.group(1),
                'graduation_year': int(year_match.group(1)),
                'phone': '',
                'work_address': '',
                'home_address': ''
            }
        
        if current_member:
            if phone_match:
                current_member['phone'] = phone_match.group(1).replace('-', '')
            
            if address_match:
                address = address_match.group(1)
                if '직장' in line or '회사' in line or '사무실' in line:
                    current_member['work_address'] = address
                else:
                    current_member['home_address'] = address
    
    # 마지막 회원 추가
    if current_member:
        members.append(current_member)
    
    return members
# Vercel serverless 환경에서는 /tmp만 쓰기 가능
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except:
    pass  # Vercel에서는 /tmp가 이미 존재

# Jinja2 필터 등록
app.jinja_env.filters['format_phone'] = format_phone

# Supabase 설정
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_ANON_KEY', '')

# Supabase 클라이언트는 필요할 때 생성
supabase: Client = None

def get_supabase():
    """Supabase 클라이언트를 반환 (lazy initialization)"""
    global supabase
    if supabase is None:
        if not SUPABASE_URL or not SUPABASE_KEY:
            raise Exception("SUPABASE_URL and SUPABASE_ANON_KEY must be set")
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    return supabase

def hash_sensitive_data(data):
    if not data:
        return None
    return hashlib.sha256(data.encode()).hexdigest()[:8] + "***"

def init_db():
    """Supabase 테이블 초기화 및 기본 데이터 설정"""
    try:
        # Supabase 연결 확인
        if not SUPABASE_URL or SUPABASE_URL == 'https://your-project.supabase.co':
            print("Warning: SUPABASE_URL not configured")
            return
        
        if not SUPABASE_KEY or SUPABASE_KEY == 'your-anon-key':
            print("Warning: SUPABASE_ANON_KEY not configured")
            return
        
        supabase = get_supabase()
        
        # 기본 관리자 계정 확인 및 생성
        admin_check = get_supabase().table('users').select('*').eq('name', '관리자').execute()
        if not admin_check.data:
            admin_password = generate_password_hash('admin1234')
            get_supabase().table('users').insert({
                'name': '관리자',
                'password': admin_password,
                'is_admin': True
            }).execute()
        
        # 기본 설정값 확인 및 추가
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
            existing = get_supabase().table('settings').select('*').eq('key', key).execute()
            if not existing.data:
                get_supabase().table('settings').insert({'key': key, 'value': value}).execute()
                
    except Exception as e:
        print(f"Database initialization error: {e}")
        # Vercel에서는 에러가 발생해도 앱이 시작되도록 함

def log_activity(action, target_user=None, details=None):
    try:
        supabase = get_supabase()
        get_supabase().table('activity_logs').insert({
            'action': action,
            'target_user': target_user,
            'details': details,
            'performed_by': session.get('user_name', 'System')
        }).execute()
    except:
        pass

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # 사이트 이름 가져오기
        result = get_supabase().table('settings').select('value').eq('key', 'site_name').execute()
        site_name = result.data[0]['value'] if result.data else '금호중앙동문회'
        
        # 갤러리 이미지 가져오기
        gallery_result = get_supabase().table('gallery').select('*').order('created_at', desc=True).limit(5).execute()
        gallery_images = gallery_result.data
        
        return render_template('index.html', site_name=site_name, gallery_images=gallery_images)
    except Exception as e:
        flash(f'데이터베이스 오류: {e}')
        return render_template('index.html', site_name='금호중앙동문회', gallery_images=[])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['name']
        password = request.form['password']
        
        try:
            result = get_supabase().table('users').select('*').eq('name', name).execute()
            user = result.data[0] if result.data else None
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['user_year'] = user.get('graduation_year')
                session['is_admin'] = user.get('is_admin', False)
                session['is_student'] = user.get('is_student', False)
                log_activity('로그인', user['name'])
                return redirect(url_for('index'))
            else:
                flash('이름 또는 비밀번호가 잘못되었습니다.')
        except Exception as e:
            flash(f'로그인 오류: {e}')
    
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
    
    try:
        query = get_supabase().table('users').select('*').neq('name', '관리자')
        
        if search:
            query = query.ilike('name', f'%{search}%')
        
        if year_filter:
            query = query.eq('graduation_year', year_filter)
        
        users_result = query.order('graduation_year', desc=True).order('name').execute()
        users = users_result.data
        
        # 기수 목록 가져오기
        years_result = get_supabase().table('users').select('graduation_year').not_.is_('graduation_year', 'null').execute()
        years = sorted(list(set([user['graduation_year'] for user in years_result.data if user['graduation_year']])), reverse=True)
        
        is_admin_or_student = session.get('is_admin') or session.get('is_student')
        
        return render_template('directory.html', users=users, years=years, 
                             search=search, year_filter=year_filter, 
                             is_admin_or_student=is_admin_or_student)
    except Exception as e:
        flash(f'데이터베이스 오류: {e}')
        return render_template('directory.html', users=[], years=[], 
                             search=search, year_filter=year_filter, 
                             is_admin_or_student=False)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        result = get_supabase().table('users').select('*').eq('id', session['user_id']).execute()
        user = result.data[0] if result.data else None
        return render_template('profile.html', user=user)
    except Exception as e:
        flash(f'프로필 로드 오류: {e}')
        return redirect(url_for('index'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    phone = request.form['phone']
    work_address = request.form['work_address']
    home_address = request.form['home_address']
    phone_public = 'phone_public' in request.form
    work_address_public = 'work_address_public' in request.form
    home_address_public = 'home_address_public' in request.form
    new_password = request.form.get('new_password')
    
    try:
        update_data = {
            'phone': phone,
            'work_address': work_address,
            'home_address': home_address,
            'phone_public': phone_public,
            'work_address_public': work_address_public,
            'home_address_public': home_address_public
        }
        
        if new_password:
            update_data['password'] = generate_password_hash(new_password)
            log_activity('비밀번호 변경', session['user_name'])
        
        get_supabase().table('users').update(update_data).eq('id', session['user_id']).execute()
        log_activity('프로필 수정', session['user_name'])
        flash('프로필이 업데이트되었습니다.')
    except Exception as e:
        flash(f'프로필 업데이트 오류: {e}')
    
    return redirect(url_for('profile'))

@app.route('/notices')
def notices():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        result = get_supabase().table('notices').select('*').order('created_at', desc=True).execute()
        notices = result.data
        return render_template('notices.html', notices=notices)
    except Exception as e:
        flash(f'공지사항 로드 오류: {e}')
        return render_template('notices.html', notices=[])

@app.route('/notice/<int:notice_id>')
def notice_detail(notice_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        notice_result = get_supabase().table('notices').select('*').eq('id', notice_id).execute()
        notice = notice_result.data[0] if notice_result.data else None
        
        comments_result = get_supabase().table('comments').select('*').eq('notice_id', notice_id).order('created_at').execute()
        comments = comments_result.data
        
        return render_template('notice_detail.html', notice=notice, comments=comments)
    except Exception as e:
        flash(f'공지사항 로드 오류: {e}')
        return redirect(url_for('notices'))

@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    notice_id = request.form['notice_id']
    content = request.form['content']
    
    try:
        author_name = session['user_name']
        if session['user_name'] != '관리자' and session.get('user_year'):
            author_name = f"{session.get('user_year')}기 {session['user_name']}"
        
        get_supabase().table('comments').insert({
            'notice_id': notice_id,
            'author': author_name,
            'content': content
        }).execute()
        
        return redirect(url_for('notice_detail', notice_id=notice_id))
    except Exception as e:
        flash(f'댓글 작성 오류: {e}')
        return redirect(url_for('notice_detail', notice_id=notice_id))

@app.route('/finances')
def finances():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        # 설정 확인
        finance_public_result = get_supabase().table('settings').select('value').eq('key', 'finance_public').execute()
        finance_public = finance_public_result.data[0]['value'] == '1' if finance_public_result.data else True
        
        finance_details_public_result = get_supabase().table('settings').select('value').eq('key', 'finance_details_public').execute()
        finance_details_public = finance_details_public_result.data[0]['value'] == '1' if finance_details_public_result.data else True
        
        bank_info_public_result = get_supabase().table('settings').select('value').eq('key', 'bank_info_public').execute()
        bank_info_public = bank_info_public_result.data[0]['value'] == '1' if bank_info_public_result.data else True
        
        if not finance_public and not session.get('is_admin'):
            flash('회계 정보는 현재 비공개 상태입니다.')
            return redirect(url_for('index'))
        
        finances = []
        if finance_details_public or session.get('is_admin'):
            finances_result = get_supabase().table('finances').select('*').order('date', desc=True).execute()
            finances = finances_result.data
        
        # 수입/지출 합계 계산
        all_finances = get_supabase().table('finances').select('type, amount').execute()
        total_income = sum(f['amount'] for f in all_finances.data if f['type'] == 'income')
        total_expense = sum(f['amount'] for f in all_finances.data if f['type'] == 'expense')
        
        bank_info = {}
        if bank_info_public or session.get('is_admin'):
            bank_settings = get_supabase().table('settings').select('key, value').in_('key', ['bank_name', 'account_number', 'account_holder']).execute()
            bank_info = {item['key']: item['value'] for item in bank_settings.data}
        
        balance = total_income - total_expense
        
        return render_template('finances.html', finances=finances, 
                             total_income=total_income, total_expense=total_expense, balance=balance,
                             bank_info=bank_info, finance_public=finance_public,
                             finance_details_public=finance_details_public,
                             bank_info_public=bank_info_public)
    except Exception as e:
        flash(f'회계 정보 로드 오류: {e}')
        return render_template('finances.html', finances=[], 
                             total_income=0, total_expense=0, balance=0,
                             bank_info={}, finance_public=True,
                             finance_details_public=True,
                             bank_info_public=True)

@app.route('/events')
def events():
    if 'user_id' not in session or not (session.get('is_admin') or session.get('is_student')):
        flash('접근 권한이 없습니다.')
        return redirect(url_for('index'))
    
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')
    
    try:
        # 모든 사용자 가져오기
        users_query = get_supabase().table('users').select('id, name, graduation_year, phone, work_address, home_address').neq('name', '관리자')
        
        if search:
            users_query = users_query.ilike('name', f'%{search}%')
        
        users_result = users_query.order('graduation_year', desc=True).order('name').execute()
        users = users_result.data
        
        # 모든 이벤트 가져오기
        events_result = get_supabase().table('events').select('user_id, attendance_status, notes').execute()
        events_dict = {event['user_id']: event for event in events_result.data}
        
        # 사용자와 이벤트 정보 결합
        users_events = []
        for user in users:
            event = events_dict.get(user['id'], {})
            users_events.append({
                'id': user['id'],
                'name': user['name'],
                'graduation_year': user['graduation_year'],
                'phone': user.get('phone', ''),
                'work_address': user.get('work_address', ''),
                'home_address': user.get('home_address', ''),
                'status': event.get('attendance_status', '무응답'),
                'notes': event.get('notes', '')
            })
        
        # 상태 필터 적용
        if status_filter:
            users_events = [u for u in users_events if u['status'] == status_filter]
        
        # 상태별 인원 수 계산
        status_counts = {}
        for user_event in users_events:
            status = user_event['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return render_template('events.html', users_events=users_events, status_counts=status_counts, 
                             status_filter=status_filter, search=search)
    except Exception as e:
        flash(f'행사 정보 로드 오류: {e}')
        return render_template('events.html', users_events=[], status_counts={}, 
                             status_filter=status_filter, search=search)

@app.route('/update_attendance', methods=['POST'])
def update_attendance():
    if 'user_id' not in session or not session.get('is_student'):
        return jsonify({'success': False})
    
    user_id = request.form['user_id']
    status = request.form['status']
    notes = request.form.get('notes', '')
    
    try:
        # 기존 이벤트 삭제
        get_supabase().table('events').delete().eq('user_id', user_id).execute()
        
        # 새 이벤트 추가
        get_supabase().table('events').insert({
            'user_id': user_id,
            'attendance_status': status,
            'notes': notes,
            'updated_by': session['user_name']
        }).execute()
        
        user_result = get_supabase().table('users').select('name').eq('id', user_id).execute()
        user_name = user_result.data[0]['name'] if user_result.data else 'Unknown'
        
        log_activity('참석상태 변경', user_name, f'{status} - {notes}')
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/gallery')
def gallery():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        result = get_supabase().table('gallery').select('*').order('created_at', desc=True).execute()
        images = result.data
        return render_template('gallery.html', images=images)
    except Exception as e:
        flash(f'갤러리 로드 오류: {e}')
        return render_template('gallery.html', images=[])

# 관리자 라우트들
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
    
    try:
        result = get_supabase().table('users').select('*').order('graduation_year', desc=True).order('name').execute()
        users = result.data
        return render_template('admin_users.html', users=users)
    except Exception as e:
        flash(f'사용자 목록 로드 오류: {e}')
        return render_template('admin_users.html', users=[])

@app.route('/admin/add_user', methods=['POST'])
def add_user():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    name = request.form['name']
    graduation_year = request.form['graduation_year']
    phone = request.form['phone']
    work_address = request.form['work_address']
    home_address = request.form['home_address']
    is_student = 'is_student' in request.form
    password = generate_password_hash(f"{name}1234")
    
    try:
        user_result = get_supabase().table('users').insert({
            'name': name,
            'password': password,
            'graduation_year': int(graduation_year),
            'phone': phone,
            'work_address': work_address,
            'home_address': home_address,
            'is_student': is_student
        }).execute()
        
        user_id = user_result.data[0]['id']
        get_supabase().table('events').insert({'user_id': user_id}).execute()
        
        log_activity('동문 추가', name, f'{graduation_year}기')
        flash(f'{name} 동문이 추가되었습니다. 초기 비밀번호: {name}1234')
    except Exception as e:
        flash(f'동문 추가 오류: {e}')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    try:
        # 사용자 이름 가져오기
        user_result = get_supabase().table('users').select('name').eq('id', user_id).execute()
        user_name = user_result.data[0]['name'] if user_result.data else 'Unknown'
        
        # 관리자는 삭제 불가
        if user_name == '관리자':
            flash('관리자 계정은 삭제할 수 없습니다.')
            return redirect(url_for('admin_users'))
        
        # 사용자 삭제 (CASCADE로 관련 데이터도 자동 삭제됨)
        get_supabase().table('users').delete().eq('id', user_id).execute()
        
        log_activity('동문 삭제', user_name)
        flash(f'{user_name} 동문이 삭제되었습니다.')
    except Exception as e:
        flash(f'동문 삭제 오류: {e}')
    
    return redirect(url_for('admin_users'))

@app.route('/admin/add_finance', methods=['POST'])
def add_finance():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    finance_type = request.form['type']
    description = request.form['description']
    amount = request.form['amount']
    
    try:
        get_supabase().table('finances').insert({
            'type': finance_type,
            'description': description,
            'amount': int(amount),
            'created_by': session['user_name']
        }).execute()
        
        log_activity('회계 내역 추가', None, f'{finance_type}: {description} - {amount}원')
        flash('회계 내역이 추가되었습니다.')
    except Exception as e:
        flash(f'회계 내역 추가 오류: {e}')
    
    return redirect(url_for('finances'))

@app.route('/admin/delete_finance/<finance_id>', methods=['POST'])
def delete_finance(finance_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    try:
        get_supabase().table('finances').delete().eq('id', finance_id).execute()
        log_activity('회계 내역 삭제', None, f'ID: {finance_id}')
        flash('회계 내역이 삭제되었습니다.')
    except Exception as e:
        flash(f'회계 내역 삭제 오류: {e}')
    
    return redirect(url_for('finances'))

@app.route('/admin/bulk_upload', methods=['POST'])
def bulk_upload():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('index'))
    
    if 'file' not in request.files:
        flash('파일이 선택되지 않았습니다.')
        return redirect(url_for('admin_users'))
    
    file = request.files['file']
    if file.filename == '':
        flash('파일이 선택되지 않았습니다.')
        return redirect(url_for('admin_users'))
    
    if file and allowed_file(file.filename):
        try:
            # 파일 내용 읽기
            file_content = file.read()
            file.seek(0)  # 파일 포인터 리셋
            
            text = ""
            if file.filename.lower().endswith('.pdf'):
                text = extract_text_from_pdf(io.BytesIO(file_content))
            elif file.filename.lower().endswith('.txt'):
                text = file_content.decode('utf-8')
            elif file.filename.lower().endswith('.csv'):
                text = file_content.decode('utf-8')
            
            # 회원 정보 파싱
            members = parse_member_data(text)
            
            if not members:
                flash('파일에서 회원 정보를 찾을 수 없습니다.')
                return redirect(url_for('admin_users'))
            
            # 회원 일괄 등록
            success_count = 0
            error_count = 0
            
            for member in members:
                try:
                    # 중복 확인
                    existing = get_supabase().table('users').select('*').eq('name', member['name']).execute()
                    if existing.data:
                        error_count += 1
                        continue
                    
                    password = generate_password_hash(f"{member['name']}1234")
                    
                    user_result = get_supabase().table('users').insert({
                        'name': member['name'],
                        'password': password,
                        'graduation_year': member['graduation_year'],
                        'phone': member['phone'],
                        'work_address': member['work_address'],
                        'home_address': member['home_address'],
                        'is_student': False
                    }).execute()
                    
                    user_id = user_result.data[0]['id']
                    get_supabase().table('events').insert({'user_id': user_id}).execute()
                    
                    success_count += 1
                    log_activity('대량 동문 추가', member['name'], f'{member["graduation_year"]}기')
                    
                except Exception as e:
                    error_count += 1
                    continue
            
            flash(f'일괄 등록 완료: 성공 {success_count}명, 실패 {error_count}명')
            
        except Exception as e:
            flash(f'파일 처리 오류: {e}')
    else:
        flash('지원하지 않는 파일 형식입니다. PDF, TXT, CSV 파일만 업로드 가능합니다.')
    
    return redirect(url_for('admin_users'))
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
else:
    # Vercel serverless 환경에서 실행될 때
    init_db()