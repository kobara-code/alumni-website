import sys
import os

# 프로젝트 루트를 Python 경로에 추가
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel은 app 객체를 직접 사용
# handler 함수가 아닌 app 객체를 export
