# Vercel 배포 가이드

## 배포 전 준비사항

### 1. Vercel 계정 생성
- [Vercel](https://vercel.com)에 가입하세요
- GitHub 계정으로 로그인하는 것을 권장합니다

### 2. 프로젝트를 GitHub에 푸시
```bash
git add .
git commit -m "Vercel 배포 준비"
git push origin main
```

## Vercel 배포 방법

### 방법 1: Vercel CLI 사용 (권장)

1. Vercel CLI 설치:
```bash
npm install -g vercel
```

2. 프로젝트 디렉토리에서 배포:
```bash
vercel
```

3. 첫 배포 시 질문에 답변:
- Set up and deploy? → Y
- Which scope? → 본인 계정 선택
- Link to existing project? → N
- Project name? → 원하는 프로젝트 이름 입력
- In which directory is your code located? → ./

4. 환경 변수 설정:
```bash
vercel env add SUPABASE_URL
vercel env add SUPABASE_ANON_KEY
vercel env add SECRET_KEY
```

5. 프로덕션 배포:
```bash
vercel --prod
```

### 방법 2: Vercel 웹 대시보드 사용

1. [Vercel Dashboard](https://vercel.com/dashboard)에 로그인

2. "New Project" 클릭

3. GitHub 저장소 연결:
   - Import Git Repository 선택
   - 본인의 저장소 선택

4. 프로젝트 설정:
   - Framework Preset: Other
   - Build Command: (비워두기)
   - Output Directory: (비워두기)

5. 환경 변수 추가:
   - Environment Variables 섹션에서 추가:
     - `SUPABASE_URL`: Supabase 프로젝트 URL
     - `SUPABASE_ANON_KEY`: Supabase anon key
     - `SECRET_KEY`: Flask secret key (랜덤 문자열)

6. "Deploy" 클릭

## 환경 변수 설정

Vercel 대시보드에서 다음 환경 변수를 설정해야 합니다:

- `SUPABASE_URL`: Supabase 프로젝트 URL
- `SUPABASE_ANON_KEY`: Supabase anonymous key
- `SECRET_KEY`: Flask 세션용 비밀 키

### Supabase 정보 확인 방법:
1. [Supabase Dashboard](https://supabase.com/dashboard)에 로그인
2. 프로젝트 선택
3. Settings → API 메뉴에서 확인:
   - Project URL → `SUPABASE_URL`
   - anon public → `SUPABASE_ANON_KEY`

## 배포 후 확인사항

1. 배포 완료 후 제공되는 URL로 접속
2. 로그인 테스트 (기본 관리자: 관리자/admin1234)
3. 데이터베이스 연결 확인
4. 파일 업로드 기능 테스트

## 문제 해결

### 배포 실패 시:
- Vercel 대시보드의 Deployments → 실패한 배포 → Logs 확인
- 환경 변수가 올바르게 설정되었는지 확인
- requirements.txt의 패키지 버전 호환성 확인

### 정적 파일 문제:
- static/uploads 폴더는 Vercel의 serverless 환경에서 영구 저장되지 않습니다
- 파일 업로드는 Supabase Storage 사용을 권장합니다

### 데이터베이스 연결 오류:
- Supabase URL과 Key가 정확한지 확인
- Supabase 프로젝트가 활성화되어 있는지 확인

## 추가 설정

### 커스텀 도메인 연결:
1. Vercel Dashboard → 프로젝트 선택
2. Settings → Domains
3. 도메인 추가 및 DNS 설정

### 자동 배포 설정:
- GitHub 저장소에 푸시하면 자동으로 배포됩니다
- main 브랜치 → 프로덕션 배포
- 다른 브랜치 → 프리뷰 배포

## 참고 링크

- [Vercel 문서](https://vercel.com/docs)
- [Vercel Python 런타임](https://vercel.com/docs/functions/serverless-functions/runtimes/python)
- [Supabase 문서](https://supabase.com/docs)
