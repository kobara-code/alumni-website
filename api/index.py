import sys
import os

# 프로젝트 루트를 Python 경로에 추가
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)

# app 모듈 import
from app import app as application

# Vercel이 찾을 수 있도록 app 변수로도 export
app = application
