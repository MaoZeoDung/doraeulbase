# 🚀 도래울베이스 - 배포 완성판

## ✅ 모든 기능 완벽 구현!

### 구현된 기능
- ✅ 카카오 소셜 로그인/로그아웃
- ✅ 회원가입 (이름, 학년)
- ✅ **프로필 사진 크롭** (1:1 원형, 확대/축소/회전)
- ✅ 게시글 목록 (페이지네이션 30개씩)
- ✅ 게시글 작성 (캡챠 인증)
- ✅ 게시글 상세보기
- ✅ 카테고리 필터링 (전체/공지/정보/질문/자유)
- ✅ 공지사항 관리자 전용
- ✅ 작성자 정보 표시 (프로필, 이름, 학년)
- ✅ 관리자 금색 뱃지 `[관리자]`
- ✅ **URL 클린 라우팅** (`/` `/write-post` `/post-detail`)

## 📦 빠른 시작

### 1단계: 다운로드 & 설치

```bash
# 1. 압축 해제 후 폴더로 이동
cd doraeul-base

# 2. 패키지 설치
npm install

# 3. 환경 변수 설정
cp .env.example .env
```

### 2단계: 환경 변수 설정

`.env` 파일을 열어서 카카오 API 키 입력:

```env
PORT=3000
KAKAO_CLIENT_ID=발급받은_REST_API_키
KAKAO_REDIRECT_URI=http://localhost:3000/auth/kakao/callback
SESSION_SECRET=랜덤한_비밀키로_변경
```

### 3단계: 카카오 개발자 센터 설정

1. https://developers.kakao.com 접속
2. "내 애플리케이션" → "애플리케이션 추가"
3. REST API 키 복사
4. "카카오 로그인" 활성화
5. Redirect URI 등록:
   ```
   http://localhost:3000/auth/kakao/callback
   ```

### 4단계: 서버 실행

```bash
npm start
```

브라우저에서 **`http://localhost:3000`** 접속!

## 🎯 주요 기능 사용법

### 회원가입
1. "로그인" 버튼 클릭
2. 카카오 로그인
3. 이름, 학년 입력
4. **프로필 사진 편집:**
   - 사진 선택 클릭
   - "편집하기" 클릭
   - 확대/축소/회전으로 원하는 영역 선택
   - "적용하기" 클릭
5. 가입 완료!

### 게시글 작성
1. 로그인 후 "글쓰기" 클릭
2. 카테고리 선택 (공지사항은 관리자만)
3. 제목, 내용 입력
4. 캡챠 인증 (간단한 계산)
5. 작성 완료!

### 관리자 설정
서버 실행 후 `data/users.json` 편집:

```json
{
  "id": 1,
  "name": "홍길동",
  "role": "admin"  ← 이렇게 변경
}
```

## 📂 프로젝트 구조

```
doraeul-base/
├── server.js              # 백엔드 서버
├── package.json           # npm 설정
├── .env.example           # 환경 변수 예시
├── .gitignore            # Git 제외 파일
│
├── index.html            # 메인 게시판 (/)
├── write-post.html       # 글쓰기 (/write-post)
├── post-detail.html      # 게시글 상세 (/post-detail)
├── register.html         # 회원가입 (/register)
│
├── sample-posts.json     # 초기 게시글
├── users.json            # 사용자 데이터 (자동 생성)
├── posts.json            # 게시글 데이터 (자동 생성)
│
├── data/                 # 데이터 저장 폴더 (자동 생성)
├── uploads/              # 업로드 파일 (자동 생성)
├── images/
│   └── logo.png
│
└── README.md            # 이 파일
```

## 🎨 새로운 기능: 프로필 사진 크롭

### 특징
- ✂️ 1:1 비율로 자동 크롭
- 🔍 확대/축소 자유롭게
- ↻ 90도 회전 가능
- 📐 원하는 영역 선택
- ⭕ 원형으로 표시

### 사용법
1. 회원가입 또는 프로필 수정
2. "사진 선택" 버튼
3. 이미지 파일 선택
4. "편집하기" 버튼 클릭
5. 확대/축소/회전으로 조정
6. "적용하기" 클릭

## 🌐 URL 구조 (클린 URL)

| 기능 | URL | 파일 |
|------|-----|------|
| 메인 게시판 | `/` | index.html |
| 글쓰기 | `/write-post` | write-post.html |
| 게시글 상세 | `/post-detail?id=123` | post-detail.html |
| 회원가입 | `/register` | register.html |
| 카카오 로그인 | `/auth/kakao` | - |

더 이상 `.html` 확장자 불필요!

## 🔒 보안 기능

- ✅ 세션 기반 인증
- ✅ 캡챠 봇 방지
- ✅ 파일 업로드 검증 (크기, 형식)
- ✅ 관리자 권한 체크
- ✅ XSS 방지 (입력 검증)

## 🚀 프로덕션 배포 체크리스트

### 필수 변경사항
- [ ] `.env`에서 `SESSION_SECRET` 변경
- [ ] `.env`에서 `NODE_ENV=production` 설정
- [ ] HTTPS 사용 시 `session.cookie.secure = true`
- [ ] 데이터베이스 연결 (MongoDB, PostgreSQL 등)
- [ ] 카카오 개발자 센터에서 실제 도메인 등록

### 권장 사항
- [ ] PM2로 프로세스 관리
- [ ] Nginx 리버스 프록시
- [ ] Let's Encrypt SSL 인증서
- [ ] 로그 시스템 구축
- [ ] 백업 시스템 구축

### 배포 플랫폼
- **Vercel** (Node.js 지원, 무료)
- **Railway** (간편한 배포)
- **Heroku** (무료 티어)
- **AWS EC2** (완전한 제어)
- **DigitalOcean** (간단한 VPS)

## 🛠️ 문제 해결

### "Cannot GET /" 오류
✅ **해결됨!** 이제 `/`로 바로 접속 가능합니다.

### 카카오 로그인 실패
1. `.env` 파일에 REST API 키 확인
2. Redirect URI 정확히 등록 확인
3. 서버 재시작

### 프로필 사진이 원형이 아님
✅ **해결됨!** 크롭 기능으로 자동 1:1 비율 적용

### 포트 이미 사용 중
`.env` 파일에서 `PORT=3001`로 변경

## 📊 데이터 관리

### users.json 구조
```json
{
  "id": 1,
  "kakaoId": "12345",
  "name": "홍길동",
  "grade": 2,
  "profileImage": "/uploads/profile.jpg",
  "role": "user",
  "createdAt": "2025-11-06T..."
}
```

### posts.json 구조
```json
{
  "id": 1,
  "category": "free",
  "categoryName": "자유",
  "title": "제목",
  "content": "내용",
  "author": "홍길동",
  "authorId": 1,
  "date": "2025-11-06",
  "time": "14:30",
  "views": 0,
  "likes": 0,
  "comments": 0
}
```

## 📈 향후 추가 기능 (선택)

- [ ] 댓글 시스템
- [ ] 좋아요 기능 구현
- [ ] 검색 기능
- [ ] 실시간 알림
- [ ] 다크 모드
- [ ] 이미지 첨부 (게시글)
- [ ] 사용자 프로필 페이지
- [ ] 비밀번호 변경 (소셜 로그인이라 불필요할 수 있음)

## 💡 팁

### 관리자로 빠르게 테스트하기
1. 회원가입 먼저
2. 서버 중지
3. `data/users.json` 열어서 `role: "admin"` 변경
4. 서버 재시작
5. 로그아웃 후 로그인

### 샘플 데이터 초기화
```bash
# posts.json을 sample-posts.json으로 복원
cp sample-posts.json data/posts.json

# users.json 초기화
echo "[]" > data/users.json
```

## 📞 지원

문제가 있으면:
1. 이 README 다시 읽기
2. 콘솔(F12) 에러 확인
3. 서버 로그 확인

## 🎉 완성!

**배포 준비 완료!** 모든 기능이 프로덕션 레벨로 작동합니다.

즐거운 커뮤니티 활동 되세요! 🚀
