# 금호중앙동문회 웹사이트

Flask 기반의 동문회 관리 웹사이트입니다.

## 주요 기능

### 기본 기능
- **로그인 시스템**: 이름과 비밀번호로 간단 로그인
- **동문 수첩**: 기수별 정렬, 검색 기능, 개인정보 공개 설정
- **공지사항**: 관리자 작성, 댓글 기능, 이미지 첨부 가능
- **개인 정보 관리**: 비밀번호 변경, 연락처/주소 공개 설정

### 권한별 기능
- **관리자**: 모든 기능 접근, 동문 관리, 시스템 설정
- **재학생**: 행사 참석 관리, 정보 변경 요청
- **일반 동문**: 기본 정보 조회 및 개인정보 수정

### 고급 기능
- **행사 참석 관리**: 재학생이 동문들의 참석 상태 관리
- **회계 관리**: 수입/지출 내역, 세분화된 공개 설정
- **변경 요청 시스템**: 재학생이 요청하고 관리자가 승인
- **활동 로그**: 모든 중요 활동 기록
- **사진 갤러리**: 동문회 사진 관리

## 보안 강화 사항

1. **세션 보안**: 강화된 시크릿 키 사용
2. **파일 업로드 보안**: 안전한 파일명 처리
3. **SQL 인젝션 방지**: 매개변수화된 쿼리 사용
4. **권한 검증**: 모든 중요 기능에 권한 확인
5. **활동 로깅**: 모든 중요 활동 기록 및 추적
6. **민감정보 보호**: 개인정보 공개 설정 세분화

## 설치 및 실행

### Supabase 설정

1. **Supabase 프로젝트 생성**
   - [supabase.com](https://supabase.com)에서 계정 생성
   - 새 프로젝트 생성
   - 프로젝트 설정에서 API URL과 anon key 확인

2. **환경 변수 설정**
   - `.env.example`을 `.env`로 복사
   - Supabase URL과 anon key를 설정
   ```bash
   cp .env.example .env
   # .env 파일을 편집하여 실제 값으로 변경
   ```

3. **데이터베이스 마이그레이션**
   - Supabase 대시보드의 SQL Editor에서 `supabase/migrations/create_tables.sql` 실행
   - 또는 Supabase CLI 사용 (선택사항)

4. **애플리케이션 실행**:
```bash
python app.py
```

5. 브라우저에서 `http://localhost:5000` 접속

## 기본 계정

- **관리자**: 이름 `관리자`, 비밀번호 `admin1234`

## 사용법

1. 관리자로 로그인 후 동문 등록 (재학생 권한 설정 가능)
2. 등록된 동문은 `이름1234` 형식의 초기 비밀번호로 로그인
3. 개인 정보 수정에서 비밀번호 변경 및 공개 설정 가능
4. 재학생은 행사 참석 관리 및 정보 변경 요청 가능
5. 관리자는 모든 설정 및 요청 관리 가능

## 데이터베이스

Supabase PostgreSQL 데이터베이스를 사용합니다.
- 클라우드 기반으로 별도 설치 불필요
- 실시간 기능 지원
- 자동 백업 및 확장성

## 보안 주의사항

- 실제 운영시 환경 변수로 시크릿 키 관리
- HTTPS 사용 권장
- Supabase RLS(Row Level Security) 정책 확인
- 업로드 폴더 권한 설정 확인

## 배포

### Render 배포 가이드

1. **GitHub 저장소 생성**
   - GitHub에서 새 저장소 생성
   - 저장소명: `alumni-website`

2. **코드 업로드**
   ```bash
   cd C:\alumni_website
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/[사용자명]/alumni-website.git
   git push -u origin main
   ```

3. **Render 배포**
   - [render.com](https://render.com) 가입 및 로그인
   - "New Web Service" 클릭
   - GitHub 저장소 연결
   - 배포 설정:
     - **Name**: `금고중앙동문회`
     - **Environment**: `Python 3`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `python app.py`
     - **Environment Variables**: Supabase URL과 anon key 설정
   - "Create Web Service" 클릭

4. **배포 완료**
   - 자동으로 URL 생성 (예: `https://your-app.onrender.com`)
   - 첫 배포는 5-10분 소요

### 배포 후 확인사항
- ✅ 사이트 접속 확인
- ✅ Supabase 연결 확인
- ✅ 관리자 로그인: `관리자` / `admin1234`
- ✅ 기본 기능 테스트
- ✅ HTTPS 자동 적용 확인

### 주의사항
- 무료 플랜: 15분 비활성시 슬립 모드
- 첫 접속시 깨어나는데 30초 소요
- Supabase 무료 플랜: 500MB 데이터베이스, 50MB 파일 저장소
- 데이터는 Supabase 클라우드에 영구 보존됨
