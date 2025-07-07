# Supabase 설정 (무료 외부 데이터베이스)
# 1. supabase.com 가입
# 2. 새 프로젝트 생성
# 3. 아래 정보를 프로젝트에서 복사

SUPABASE_URL = "https://your-project.supabase.co"
SUPABASE_KEY = "your-anon-key"

import os

def get_supabase_config():
    return {
        'url': os.environ.get('SUPABASE_URL'),
        'key': os.environ.get('SUPABASE_KEY')
    }