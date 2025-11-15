const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';

// 데이터 저장 경로
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const POSTS_FILE = path.join(DATA_DIR, 'posts.json');
const COMMENTS_FILE = path.join(DATA_DIR, 'comments.json');
const LIKES_FILE = path.join(DATA_DIR, 'likes.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SESSIONS_DIR = path.join(__dirname, 'sessions');

// 디렉토리 생성
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// 초기 데이터 파일 생성
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(POSTS_FILE)) {
    // 기존 샘플 게시글 데이터 추가
    const samplePosts = require('./sample-posts.json');
    fs.writeFileSync(POSTS_FILE, JSON.stringify(samplePosts, null, 2));
}
if (!fs.existsSync(COMMENTS_FILE)) fs.writeFileSync(COMMENTS_FILE, '[]');
if (!fs.existsSync(LIKES_FILE)) fs.writeFileSync(LIKES_FILE, '{"posts": {}, "comments": {}}');
if (!fs.existsSync(REPORTS_FILE)) fs.writeFileSync(REPORTS_FILE, '[]');

// 프록시 신뢰 설정 (Cloudtype 등 리버스 프록시 환경용)
if (IS_PRODUCTION) {
    app.set('trust proxy', 1);
}

// 미들웨어 설정
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 세션 설정 (정적 파일보다 먼저!)
app.use(session({
    store: new FileStore({
        path: SESSIONS_DIR,
        ttl: 86400, // 24시간 (초 단위)
        retries: 0
    }),
    secret: process.env.SESSION_SECRET || 'doraeul-base-secret-key-2025',
    resave: false,
    saveUninitialized: false,
    name: 'doraeul.sid', // 커스텀 쿠키 이름
    cookie: {
        secure: IS_PRODUCTION, // 프로덕션에서는 HTTPS 필수
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24시간
        sameSite: 'lax', // 카카오 리다이렉트를 위해 lax 사용
        path: '/'
        // domain 설정 제거 - 브라우저가 자동으로 설정하도록 함
    }
}));

// 세션 디버깅 미들웨어 (문제 발생 시 주석 해제)
// app.use((req, res, next) => {
//     if (req.path.includes('/auth/kakao') || req.path.includes('/api/register') || req.path.includes('/register')) {
//         console.log('🔍 세션 체크:', {
//             path: req.path,
//             sessionID: req.sessionID,
//             hasTempUser: !!req.session.tempKakaoUser,
//             hasUser: !!req.session.user,
//             cookie: req.headers.cookie ? '있음' : '없음'
//         });
//     }
//     next();
// });

// 정적 파일 제공
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));

// 기본 라우팅 - 루트 접근 시 index.html로
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// HTML 페이지 라우팅
app.get('/write-post', (req, res) => {
    res.sendFile(path.join(__dirname, 'write-post.html'));
});

app.get('/post-detail', (req, res) => {
    res.sendFile(path.join(__dirname, 'post-detail.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// 파일 업로드 설정 (프로필 사진)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOADS_DIR);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('허용되지 않는 파일 형식입니다. (jpg, jpeg, png, gif, webp만 가능)'));
        }
    }
});

// ============= 유틸리티 함수 =============

function readJSON(filepath) {
    try {
        const data = fs.readFileSync(filepath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

function writeJSON(filepath, data) {
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
}

// ============= 카카오 로그인 설정 =============
const KAKAO_CONFIG = {
    CLIENT_ID: process.env.KAKAO_CLIENT_ID || 'NOT_SET',
    REDIRECT_URI: process.env.KAKAO_REDIRECT_URI || `http://localhost:${PORT}/auth/kakao/callback`,
    CLIENT_SECRET: process.env.KAKAO_CLIENT_SECRET || ''
};

// 환경변수 경고 (서버는 계속 실행됨)
if (!process.env.KAKAO_CLIENT_ID || KAKAO_CONFIG.CLIENT_ID === 'NOT_SET') {
    console.warn('⚠️  경고: KAKAO_CLIENT_ID 환경변수가 설정되지 않았습니다.');
    console.warn('   카카오 로그인 기능이 작동하지 않을 수 있습니다.');
}

// 카카오 로그인 페이지로 리다이렉트
app.get('/auth/kakao', (req, res) => {
    const kakaoAuthURL = `https://kauth.kakao.com/oauth/authorize?client_id=${KAKAO_CONFIG.CLIENT_ID}&redirect_uri=${KAKAO_CONFIG.REDIRECT_URI}&response_type=code`;
    res.redirect(kakaoAuthURL);
});

// 카카오 로그인 콜백
app.get('/auth/kakao/callback', async (req, res) => {
    const { code } = req.query;
    
    try {
        // 1. 토큰 받기
        const tokenResponse = await axios.post('https://kauth.kakao.com/oauth/token', null, {
            params: {
                grant_type: 'authorization_code',
                client_id: KAKAO_CONFIG.CLIENT_ID,
                redirect_uri: KAKAO_CONFIG.REDIRECT_URI,
                code: code
            },
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const accessToken = tokenResponse.data.access_token;

        // 2. 사용자 정보 받기
        const userResponse = await axios.get('https://kapi.kakao.com/v2/user/me', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        const kakaoUser = userResponse.data;
        const kakaoId = kakaoUser.id;
        const kakaoName = kakaoUser.kakao_account?.profile?.nickname || '사용자';
        const kakaoProfileImage = kakaoUser.kakao_account?.profile?.profile_image_url || null;

        // 3. 사용자 DB 확인 및 저장
        const users = readJSON(USERS_FILE);
        let user = users.find(u => u.kakaoId === kakaoId);

        if (!user) {
            // 신규 회원 - 추가 정보 입력 페이지로 리다이렉트
            req.session.tempKakaoUser = {
                kakaoId,
                kakaoName,
                kakaoProfileImage
            };

            // 세션 저장 확인 후 리다이렉트
            req.session.save((err) => {
                if (err) {
                    console.error('세션 저장 실패:', err);
                    return res.redirect('/?error=session_failed');
                }
                console.log('✅ 세션 저장 성공 - 회원가입 페이지로 이동:', req.sessionID);
                res.redirect('/register');
            });
        } else {
            // 기존 회원 - 로그인 처리
            req.session.user = user;

            req.session.save((err) => {
                if (err) {
                    console.error('세션 저장 실패:', err);
                    return res.redirect('/?error=session_failed');
                }
                console.log('✅ 기존 회원 로그인 성공:', user.name);
                res.redirect('/');
            });
        }

    } catch (error) {
        console.error('카카오 로그인 오류:', error.response?.data || error.message);
        res.redirect('/?error=login_failed');
    }
});

// 회원가입 완료 처리
app.post('/api/register', (req, res) => {
    const { name, grade } = req.body;
    const tempUser = req.session.tempKakaoUser;

    if (!tempUser) {
        console.error('회원가입 세션 만료 - 세션 ID:', req.sessionID);
        return res.status(400).json({
            success: false,
            message: '세션이 만료되었습니다. 카카오 로그인을 다시 시도해주세요.',
            redirect: true
        });
    }

    if (!name || !grade) {
        return res.status(400).json({ success: false, message: '이름과 학년을 입력해주세요.' });
    }

    const users = readJSON(USERS_FILE);
    
    const newUser = {
        id: users.length + 1,
        kakaoId: tempUser.kakaoId,
        name: name,
        grade: parseInt(grade),
        profileImage: tempUser.kakaoProfileImage,
        role: 'user', // 기본값: user, 관리자: admin
        createdAt: new Date().toISOString()
    };

    users.push(newUser);
    writeJSON(USERS_FILE, users);

    req.session.user = newUser;
    delete req.session.tempKakaoUser;

    // 세션 저장 확인
    req.session.save((err) => {
        if (err) {
            console.error('회원가입 세션 저장 실패:', err);
            return res.status(500).json({ success: false, message: '회원가입 처리 중 오류가 발생했습니다.' });
        }
        console.log('✅ 회원가입 완료:', newUser.name);
        res.json({ success: true, user: newUser });
    });
});

// 프로필 사진 업로드
app.post('/api/upload-profile', upload.single('profileImage'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    if (!req.file) {
        return res.status(400).json({ success: false, message: '파일이 업로드되지 않았습니다.' });
    }

    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === req.session.user.id);

    if (userIndex !== -1) {
        // 기존 프로필 이미지 삭제 (카카오 이미지가 아닌 경우)
        if (users[userIndex].profileImage && !users[userIndex].profileImage.includes('kakao')) {
            const oldImagePath = path.join(__dirname, users[userIndex].profileImage);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        users[userIndex].profileImage = `/uploads/${req.file.filename}`;
        writeJSON(USERS_FILE, users);

        req.session.user.profileImage = users[userIndex].profileImage;

        res.json({ 
            success: true, 
            profileImage: users[userIndex].profileImage 
        });
    } else {
        res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
    }
});

// 로그아웃
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// 현재 로그인 사용자 정보
app.get('/api/user', (req, res) => {
    if (req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.json({ success: false, user: null });
    }
});

// 임시 카카오 사용자 정보 (회원가입 페이지용)
app.get('/api/temp-user', (req, res) => {
    if (req.session.tempKakaoUser) {
        res.json({ success: true, user: req.session.tempKakaoUser });
    } else {
        res.json({ success: false, user: null });
    }
});

// 임시 사용자 정보 (회원가입 중)
app.get('/api/temp-user', (req, res) => {
    if (req.session.tempKakaoUser) {
        res.json({ success: true, user: req.session.tempKakaoUser });
    } else {
        res.json({ success: false, user: null });
    }
});

// ============= 게시글 API =============

// 게시글 목록 가져오기
app.get('/api/posts', (req, res) => {
    const posts = readJSON(POSTS_FILE);

    // 페이지네이션 파라미터
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    // 최신순 정렬 (id가 큰 것부터)
    const sortedPosts = posts.sort((a, b) => b.id - a.id);

    // 공지사항과 일반 게시글 분리
    const notices = sortedPosts.filter(p => p.category === 'notice');
    const regularPosts = sortedPosts.filter(p => p.category !== 'notice');

    // 공지사항 최신 3개
    const topNotices = notices.slice(0, 3);

    // 일반 게시글에만 페이지네이션 적용
    const paginatedPosts = regularPosts.slice(offset, offset + limit);

    // 페이지네이션 메타데이터 (일반 게시글 기준)
    const totalPosts = regularPosts.length;
    const totalPages = Math.ceil(totalPosts / limit);

    res.json({
        success: true,
        posts: paginatedPosts,
        topNotices: topNotices, // 공지사항 최신 3개
        pagination: {
            currentPage: page,
            totalPages: totalPages,
            totalPosts: totalPosts,
            totalNotices: notices.length,
            limit: limit,
            hasNextPage: page < totalPages,
            hasPrevPage: page > 1
        }
    });
});

// 게시글 상세 보기
app.get('/api/posts/:id', (req, res) => {
    const posts = readJSON(POSTS_FILE);
    const post = posts.find(p => p.id === parseInt(req.params.id));
    
    if (post) {
        // 조회수 증가
        post.views++;
        writeJSON(POSTS_FILE, posts);
        
        // 작성자 정보 가져오기
        const users = readJSON(USERS_FILE);
        const author = users.find(u => u.id === post.authorId);
        
        res.json({ 
            success: true, 
            post: {
                ...post,
                authorInfo: author ? {
                    name: author.name,
                    grade: author.grade,
                    role: author.role,
                    profileImage: author.profileImage
                } : null
            }
        });
    } else {
        res.status(404).json({ success: false, message: '게시글을 찾을 수 없습니다.' });
    }
});

// 게시글 작성 (캡챠 검증 포함)
app.post('/api/posts', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { category, title, content, captchaToken, images, files } = req.body;

    // 공지사항은 관리자만 작성 가능
    if (category === 'notice' && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '공지사항은 관리자만 작성할 수 있습니다.' });
    }

    // 캡챠 검증 (간단한 예시 - 실제로는 Google reCAPTCHA 등 사용)
    if (!captchaToken || captchaToken !== req.session.captcha) {
        return res.status(400).json({ success: false, message: '캡챠 인증에 실패했습니다.' });
    }

    const posts = readJSON(POSTS_FILE);

    const categoryNames = {
        'notice': '공지',
        'info': '정보',
        'question': '질문',
        'free': '자유'
    };

    const newPost = {
        id: posts.length > 0 ? Math.max(...posts.map(p => p.id)) + 1 : 1,
        category: category,
        categoryName: categoryNames[category],
        title: title,
        content: content,
        author: req.session.user.name,
        authorId: req.session.user.id,
        date: new Date().toISOString().split('T')[0],
        time: new Date().toTimeString().slice(0, 5),
        views: 0,
        likes: 0,
        comments: 0,
        images: images || [],
        files: files || []
    };

    posts.unshift(newPost); // 최신 글을 맨 앞에 추가
    writeJSON(POSTS_FILE, posts);

    // 캡챠 세션 삭제
    delete req.session.captcha;

    res.json({ success: true, post: newPost });
});

// 간단한 캡챠 생성 (숫자 계산)
app.get('/api/captcha', (req, res) => {
    const num1 = Math.floor(Math.random() * 10) + 1;
    const num2 = Math.floor(Math.random() * 10) + 1;
    const answer = num1 + num2;
    
    req.session.captcha = answer.toString();
    
    res.json({ 
        success: true, 
        question: `${num1} + ${num2} = ?` 
    });
});

// 캡챠 검증
app.post('/api/captcha/verify', (req, res) => {
    const { answer } = req.body;
    
    if (answer && answer.toString() === req.session.captcha) {
        res.json({ success: true, token: req.session.captcha });
    } else {
        res.json({ success: false, message: '답이 틀렸습니다.' });
    }
});

// ============= 라우팅 설정 =============
// 루트 경로
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// HTML 확장자 없이 접속 가능
app.get('/write-post', (req, res) => {
    res.sendFile(path.join(__dirname, 'write-post.html'));
});

app.get('/post-detail', (req, res) => {
    res.sendFile(path.join(__dirname, 'post-detail.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/edit-post', (req, res) => {
    res.sendFile(path.join(__dirname, 'edit-post.html'));
});

app.get('/admin-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// ============= 댓글 API =============

// 댓글 목록 가져오기
app.get('/api/comments/:postId', (req, res) => {
    const comments = readJSON(COMMENTS_FILE);
    const postComments = comments.filter(c => c.postId === parseInt(req.params.postId));
    
    // 작성자 정보 추가
    const users = readJSON(USERS_FILE);
    const commentsWithAuthor = postComments.map(comment => {
        const author = users.find(u => u.id === comment.authorId);
        return {
            ...comment,
            authorInfo: author ? {
                name: author.name,
                grade: author.grade,
                role: author.role,
                profileImage: author.profileImage
            } : null
        };
    });
    
    res.json({ success: true, comments: commentsWithAuthor });
});

// 댓글 작성
app.post('/api/comments', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { postId, content, parentId } = req.body;

    if (!content || !content.trim()) {
        return res.status(400).json({ success: false, message: '댓글 내용을 입력해주세요.' });
    }

    const comments = readJSON(COMMENTS_FILE);
    
    const newComment = {
        id: comments.length > 0 ? Math.max(...comments.map(c => c.id)) + 1 : 1,
        postId: parseInt(postId),
        parentId: parentId ? parseInt(parentId) : null,
        content: content.trim(),
        authorId: req.session.user.id,
        author: req.session.user.name,
        createdAt: new Date().toISOString(),
        likes: 0
    };

    comments.push(newComment);
    writeJSON(COMMENTS_FILE, comments);

    // 게시글 댓글 수 업데이트
    const posts = readJSON(POSTS_FILE);
    const post = posts.find(p => p.id === parseInt(postId));
    if (post) {
        post.comments++;
        writeJSON(POSTS_FILE, posts);
    }

    // 작성자 정보 추가
    const users = readJSON(USERS_FILE);
    const author = users.find(u => u.id === req.session.user.id);
    const commentWithAuthor = {
        ...newComment,
        authorInfo: author ? {
            name: author.name,
            grade: author.grade,
            role: author.role,
            profileImage: author.profileImage
        } : null
    };

    res.json({ success: true, comment: commentWithAuthor });
});

// 댓글 삭제
app.delete('/api/comments/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const comments = readJSON(COMMENTS_FILE);
    const commentIndex = comments.findIndex(c => c.id === parseInt(req.params.id));

    if (commentIndex === -1) {
        return res.status(404).json({ success: false, message: '댓글을 찾을 수 없습니다.' });
    }

    const comment = comments[commentIndex];

    // 작성자 본인 또는 관리자만 삭제 가능
    if (comment.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '권한이 없습니다.' });
    }

    const postId = comment.postId;
    let deletedCount = 0;
    
    // 대댓글도 함께 삭제
    const deleteCommentAndReplies = (commentId) => {
        const replies = comments.filter(c => c.parentId === commentId);
        replies.forEach(reply => deleteCommentAndReplies(reply.id));
        const index = comments.findIndex(c => c.id === commentId);
        if (index !== -1) {
            comments.splice(index, 1);
            deletedCount++;
        }
    };

    deleteCommentAndReplies(parseInt(req.params.id));
    writeJSON(COMMENTS_FILE, comments);

    // 게시글 댓글 수 업데이트
    const posts = readJSON(POSTS_FILE);
    const post = posts.find(p => p.id === postId);
    if (post) {
        post.comments -= deletedCount;
        if (post.comments < 0) post.comments = 0;
        writeJSON(POSTS_FILE, posts);
    }

    res.json({ success: true });
});

// ============= 좋아요 API =============

// 게시글 좋아요
app.post('/api/like/post/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const postId = parseInt(req.params.id);
    const userId = req.session.user.id;

    const likes = readJSON(LIKES_FILE);
    if (!likes.posts[postId]) {
        likes.posts[postId] = [];
    }

    const userIndex = likes.posts[postId].indexOf(userId);
    
    if (userIndex === -1) {
        // 좋아요 추가
        likes.posts[postId].push(userId);
        writeJSON(LIKES_FILE, likes);

        // 게시글 좋아요 수 업데이트
        const posts = readJSON(POSTS_FILE);
        const post = posts.find(p => p.id === postId);
        if (post) {
            post.likes++;
            writeJSON(POSTS_FILE, posts);
        }

        res.json({ success: true, liked: true, likes: likes.posts[postId].length });
    } else {
        // 좋아요 취소
        likes.posts[postId].splice(userIndex, 1);
        writeJSON(LIKES_FILE, likes);

        // 게시글 좋아요 수 업데이트
        const posts = readJSON(POSTS_FILE);
        const post = posts.find(p => p.id === postId);
        if (post) {
            post.likes--;
            writeJSON(POSTS_FILE, posts);
        }

        res.json({ success: true, liked: false, likes: likes.posts[postId].length });
    }
});

// 댓글 좋아요
app.post('/api/like/comment/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const commentId = parseInt(req.params.id);
    const userId = req.session.user.id;

    const likes = readJSON(LIKES_FILE);
    if (!likes.comments[commentId]) {
        likes.comments[commentId] = [];
    }

    const userIndex = likes.comments[commentId].indexOf(userId);
    
    if (userIndex === -1) {
        // 좋아요 추가
        likes.comments[commentId].push(userId);
        writeJSON(LIKES_FILE, likes);

        // 댓글 좋아요 수 업데이트
        const comments = readJSON(COMMENTS_FILE);
        const comment = comments.find(c => c.id === commentId);
        if (comment) {
            comment.likes++;
            writeJSON(COMMENTS_FILE, comments);
        }

        res.json({ success: true, liked: true, likes: likes.comments[commentId].length });
    } else {
        // 좋아요 취소
        likes.comments[commentId].splice(userIndex, 1);
        writeJSON(LIKES_FILE, likes);

        // 댓글 좋아요 수 업데이트
        const comments = readJSON(COMMENTS_FILE);
        const comment = comments.find(c => c.id === commentId);
        if (comment) {
            comment.likes--;
            writeJSON(COMMENTS_FILE, comments);
        }

        res.json({ success: true, liked: false, likes: likes.comments[commentId].length });
    }
});

// 좋아요 상태 확인
app.get('/api/like/status', (req, res) => {
    if (!req.session.user) {
        return res.json({ success: true, posts: {}, comments: {} });
    }

    const userId = req.session.user.id;
    const likes = readJSON(LIKES_FILE);

    const userLikes = {
        posts: {},
        comments: {}
    };

    // 사용자가 좋아요한 게시글
    for (const [postId, users] of Object.entries(likes.posts)) {
        if (users.includes(userId)) {
            userLikes.posts[postId] = true;
        }
    }

    // 사용자가 좋아요한 댓글
    for (const [commentId, users] of Object.entries(likes.comments)) {
        if (users.includes(userId)) {
            userLikes.comments[commentId] = true;
        }
    }

    res.json({ success: true, ...userLikes });
});

// ============= 프로필 API =============

// 사용자 프로필 정보
app.get('/api/profile/:userId', (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === parseInt(req.params.userId));

    if (!user) {
        return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
    }

    // 해당 사용자의 게시글 목록
    const posts = readJSON(POSTS_FILE);
    const userPosts = posts.filter(p => p.authorId === user.id);

    res.json({
        success: true,
        user: {
            id: user.id,
            name: user.name,
            grade: user.grade,
            role: user.role,
            profileImage: user.profileImage,
            createdAt: user.createdAt
        },
        posts: userPosts
    });
});

// 프로필 정보 수정
app.put('/api/profile', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { name, grade } = req.body;
    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === req.session.user.id);

    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
    }

    if (name) users[userIndex].name = name;
    if (grade) users[userIndex].grade = parseInt(grade);

    writeJSON(USERS_FILE, users);
    req.session.user = users[userIndex];

    res.json({ success: true, user: users[userIndex] });
});

// 회원 탈퇴
app.delete('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const userId = req.session.user.id;
    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === userId);

    if (userIndex !== -1) {
        const user = users[userIndex];
        if (user.profileImage && !user.profileImage.includes('kakao')) {
            const imagePath = path.join(__dirname, user.profileImage);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        users.splice(userIndex, 1);
        writeJSON(USERS_FILE, users);
    }

    req.session.destroy();
    res.json({ success: true });
});

// 프로필 사진 변경 (설정에서 사용)
app.post('/api/user/profile-image', upload.single('profileImage'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    if (!req.file) {
        return res.status(400).json({ success: false, message: '파일을 선택해주세요.' });
    }

    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === req.session.user.id);

    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
    }

    // 기존 프로필 사진 삭제 (카카오 프로필이 아닌 경우)
    const oldImage = users[userIndex].profileImage;
    if (oldImage && !oldImage.includes('kakao') && !oldImage.includes('placeholder')) {
        const oldImagePath = path.join(__dirname, oldImage);
        if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
        }
    }

    // 새 프로필 사진 경로 저장
    users[userIndex].profileImage = `/uploads/${req.file.filename}`;
    writeJSON(USERS_FILE, users);
    req.session.user = users[userIndex];

    res.json({ success: true, profileImage: users[userIndex].profileImage });
});

// 이름 변경
app.put('/api/user/name', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { name } = req.body;
    
    if (!name || name.trim().length === 0) {
        return res.status(400).json({ success: false, message: '이름을 입력해주세요.' });
    }

    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === req.session.user.id);

    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다.' });
    }

    users[userIndex].name = name.trim();
    
    // 해당 사용자의 모든 게시글의 작성자 이름도 변경
    const posts = readJSON(POSTS_FILE);
    posts.forEach(post => {
        if (post.authorId === req.session.user.id) {
            post.author = name.trim();
        }
    });
    writeJSON(POSTS_FILE, posts);

    // 댓글 작성자 이름도 변경
    const comments = readJSON(COMMENTS_FILE);
    comments.forEach(comment => {
        if (comment.authorId === req.session.user.id) {
            comment.author = name.trim();
        }
    });
    writeJSON(COMMENTS_FILE, comments);

    writeJSON(USERS_FILE, users);
    req.session.user = users[userIndex];

    res.json({ success: true, user: users[userIndex] });
});

// 회원 탈퇴 (프로필 설정용 엔드포인트)
app.delete('/api/user/delete', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const userId = req.session.user.id;
    const users = readJSON(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === userId);

    if (userIndex !== -1) {
        const user = users[userIndex];
        // 프로필 이미지 삭제
        if (user.profileImage && !user.profileImage.includes('kakao') && !user.profileImage.includes('placeholder')) {
            const imagePath = path.join(__dirname, user.profileImage);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }
        users.splice(userIndex, 1);
        writeJSON(USERS_FILE, users);
    }

    req.session.destroy();
    res.json({ success: true });
});

// ============= 게시글 수정/삭제 API =============

// 게시글 수정
app.put('/api/posts/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { title, content, category, images, files } = req.body;
    const posts = readJSON(POSTS_FILE);
    const postIndex = posts.findIndex(p => p.id === parseInt(req.params.id));

    if (postIndex === -1) {
        return res.status(404).json({ success: false, message: '게시글을 찾을 수 없습니다.' });
    }

    const post = posts[postIndex];

    // 작성자 본인 또는 관리자만 수정 가능
    if (post.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '권한이 없습니다.' });
    }

    // 공지사항은 관리자만 지정 가능
    if (category === 'notice' && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '공지사항은 관리자만 작성할 수 있습니다.' });
    }

    if (title) post.title = title;
    if (content) post.content = content;
    if (category) {
        post.category = category;
        const categoryNames = {'notice': '공지', 'info': '정보', 'question': '질문', 'free': '자유'};
        post.categoryName = categoryNames[category];
    }

    // 이미지와 파일 업데이트
    if (images !== undefined) post.images = images;
    if (files !== undefined) post.files = files;

    writeJSON(POSTS_FILE, posts);
    res.json({ success: true, post });
});

// 게시글 삭제
app.delete('/api/posts/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const posts = readJSON(POSTS_FILE);
    const postIndex = posts.findIndex(p => p.id === parseInt(req.params.id));

    if (postIndex === -1) {
        return res.status(404).json({ success: false, message: '게시글을 찾을 수 없습니다.' });
    }

    const post = posts[postIndex];

    if (post.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '권한이 없습니다.' });
    }

    posts.splice(postIndex, 1);
    writeJSON(POSTS_FILE, posts);

    const comments = readJSON(COMMENTS_FILE);
    const filteredComments = comments.filter(c => c.postId !== parseInt(req.params.id));
    writeJSON(COMMENTS_FILE, filteredComments);

    res.json({ success: true });
});

// ============= 이미지 업로드 API =============

const postImageStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOADS_DIR); },
    filename: (req, file, cb) => {
        const uniqueName = `post-${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const uploadPostImage = multer({
    storage: postImageStorage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExts.includes(ext)) { cb(null, true); }
        else { cb(new Error('허용되지 않는 파일 형식입니다.')); }
    }
});

app.post('/api/upload-post-image', uploadPostImage.single('image'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }
    if (!req.file) {
        return res.status(400).json({ success: false, message: '파일이 업로드되지 않았습니다.' });
    }
    res.json({ success: true, imageUrl: `/uploads/${req.file.filename}` });
});

// ============= 다중 이미지/파일 업로드 API =============

const postAttachmentStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, UPLOADS_DIR); },
    filename: (req, file, cb) => {
        const prefix = file.mimetype.startsWith('image/') ? 'img' : 'file';
        const uniqueName = `${prefix}-${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const uploadPostAttachments = multer({
    storage: postAttachmentStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB per file
    fileFilter: (req, file, cb) => {
        // 이미지 확장자
        const imageExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'];
        // 파일 확장자
        const fileExts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.hwp', '.zip', '.rar', '.7z'];
        const ext = path.extname(file.originalname).toLowerCase();

        if (imageExts.includes(ext) || fileExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('허용되지 않는 파일 형식입니다.'));
        }
    }
});

// 다중 파일 업로드 (최대 30개)
app.post('/api/upload-attachments', uploadPostAttachments.array('files', 30), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ success: false, message: '파일이 업로드되지 않았습니다.' });
    }

    const uploadedFiles = req.files.map(file => ({
        url: `/uploads/${file.filename}`,
        originalName: file.originalname,
        size: file.size,
        type: file.mimetype
    }));

    res.json({ success: true, files: uploadedFiles });
});

// ============= 검색 API =============

app.get('/api/search', (req, res) => {
    const query = req.query.q;
    if (!query || query.trim().length < 2) {
        return res.json({ success: true, users: [], posts: [] });
    }

    const searchTerm = query.toLowerCase();
    const users = readJSON(USERS_FILE);
    const matchedUsers = users.filter(u => u.name.toLowerCase().includes(searchTerm)).map(u => ({
        id: u.id, name: u.name, grade: u.grade, role: u.role, profileImage: u.profileImage
    }));

    const posts = readJSON(POSTS_FILE);
    const matchedPosts = posts.filter(p =>
        p.title.toLowerCase().includes(searchTerm) || p.content.toLowerCase().includes(searchTerm)
    );

    res.json({ success: true, users: matchedUsers, posts: matchedPosts });
});

// ============= 댓글 수정 API =============

app.put('/api/comments/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { content } = req.body;
    if (!content || !content.trim()) {
        return res.status(400).json({ success: false, message: '댓글 내용을 입력해주세요.' });
    }

    const comments = readJSON(COMMENTS_FILE);
    const commentIndex = comments.findIndex(c => c.id === parseInt(req.params.id));

    if (commentIndex === -1) {
        return res.status(404).json({ success: false, message: '댓글을 찾을 수 없습니다.' });
    }

    const comment = comments[commentIndex];

    // 작성자 본인 또는 관리자만 수정 가능
    if (comment.authorId !== req.session.user.id && req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '권한이 없습니다.' });
    }

    comments[commentIndex].content = content.trim();
    comments[commentIndex].updatedAt = new Date().toISOString();
    writeJSON(COMMENTS_FILE, comments);

    // 작성자 정보 추가
    const users = readJSON(USERS_FILE);
    const author = users.find(u => u.id === comment.authorId);
    const updatedComment = {
        ...comments[commentIndex],
        authorInfo: author ? {
            name: author.name,
            grade: author.grade,
            role: author.role,
            profileImage: author.profileImage
        } : null
    };

    res.json({ success: true, comment: updatedComment });
});

// ============= 신고 API =============

// 게시글 신고
app.post('/api/report/post/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { reason } = req.body;
    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '신고 사유를 입력해주세요.' });
    }

    const posts = readJSON(POSTS_FILE);
    const post = posts.find(p => p.id === parseInt(req.params.id));

    if (!post) {
        return res.status(404).json({ success: false, message: '게시글을 찾을 수 없습니다.' });
    }

    const reports = readJSON(REPORTS_FILE);

    // 중복 신고 방지
    const existingReport = reports.find(r =>
        r.type === 'post' &&
        r.targetId === parseInt(req.params.id) &&
        r.reporterId === req.session.user.id &&
        r.status === 'pending'
    );

    if (existingReport) {
        return res.status(400).json({ success: false, message: '이미 신고한 게시글입니다.' });
    }

    const newReport = {
        id: reports.length > 0 ? Math.max(...reports.map(r => r.id)) + 1 : 1,
        type: 'post',
        targetId: parseInt(req.params.id),
        targetTitle: post.title,
        targetContent: post.content.substring(0, 100),
        targetAuthorId: post.authorId,
        targetAuthor: post.author,
        reporterId: req.session.user.id,
        reporterName: req.session.user.name,
        reason: reason.trim(),
        createdAt: new Date().toISOString(),
        status: 'pending' // pending, resolved, rejected
    };

    reports.push(newReport);
    writeJSON(REPORTS_FILE, reports);

    res.json({ success: true, message: '신고가 접수되었습니다.' });
});

// 댓글 신고
app.post('/api/report/comment/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: '로그인이 필요합니다.' });
    }

    const { reason } = req.body;
    if (!reason || !reason.trim()) {
        return res.status(400).json({ success: false, message: '신고 사유를 입력해주세요.' });
    }

    const comments = readJSON(COMMENTS_FILE);
    const comment = comments.find(c => c.id === parseInt(req.params.id));

    if (!comment) {
        return res.status(404).json({ success: false, message: '댓글을 찾을 수 없습니다.' });
    }

    const reports = readJSON(REPORTS_FILE);

    // 중복 신고 방지
    const existingReport = reports.find(r =>
        r.type === 'comment' &&
        r.targetId === parseInt(req.params.id) &&
        r.reporterId === req.session.user.id &&
        r.status === 'pending'
    );

    if (existingReport) {
        return res.status(400).json({ success: false, message: '이미 신고한 댓글입니다.' });
    }

    const newReport = {
        id: reports.length > 0 ? Math.max(...reports.map(r => r.id)) + 1 : 1,
        type: 'comment',
        targetId: parseInt(req.params.id),
        targetTitle: '댓글',
        targetContent: comment.content.substring(0, 100),
        targetAuthorId: comment.authorId,
        targetAuthor: comment.author,
        postId: comment.postId,
        reporterId: req.session.user.id,
        reporterName: req.session.user.name,
        reason: reason.trim(),
        createdAt: new Date().toISOString(),
        status: 'pending'
    };

    reports.push(newReport);
    writeJSON(REPORTS_FILE, reports);

    res.json({ success: true, message: '신고가 접수되었습니다.' });
});

// 신고 목록 조회 (관리자 전용)
app.get('/api/reports', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '관리자만 접근 가능합니다.' });
    }

    const reports = readJSON(REPORTS_FILE);
    const { status, page = 1, limit = 10 } = req.query;

    let filteredReports = reports;
    if (status) {
        filteredReports = reports.filter(r => r.status === status);
    }

    // 최신순 정렬
    filteredReports.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    // 페이지네이션
    const startIndex = (parseInt(page) - 1) * parseInt(limit);
    const endIndex = startIndex + parseInt(limit);
    const paginatedReports = filteredReports.slice(startIndex, endIndex);

    res.json({
        success: true,
        reports: paginatedReports,
        total: filteredReports.length,
        page: parseInt(page),
        totalPages: Math.ceil(filteredReports.length / parseInt(limit))
    });
});

// 신고 처리 (관리자 전용)
app.put('/api/reports/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '관리자만 접근 가능합니다.' });
    }

    const { status, adminNote } = req.body;
    if (!['resolved', 'rejected'].includes(status)) {
        return res.status(400).json({ success: false, message: '잘못된 상태값입니다.' });
    }

    const reports = readJSON(REPORTS_FILE);
    const reportIndex = reports.findIndex(r => r.id === parseInt(req.params.id));

    if (reportIndex === -1) {
        return res.status(404).json({ success: false, message: '신고 내역을 찾을 수 없습니다.' });
    }

    reports[reportIndex].status = status;
    reports[reportIndex].adminNote = adminNote || '';
    reports[reportIndex].processedAt = new Date().toISOString();
    reports[reportIndex].processedBy = req.session.user.name;

    writeJSON(REPORTS_FILE, reports);

    res.json({ success: true, report: reports[reportIndex] });
});

// 관리자 대시보드 통계
app.get('/api/admin/stats', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: '관리자만 접근 가능합니다.' });
    }

    const users = readJSON(USERS_FILE);
    const posts = readJSON(POSTS_FILE);
    const comments = readJSON(COMMENTS_FILE);
    const reports = readJSON(REPORTS_FILE);

    const stats = {
        totalUsers: users.length,
        totalPosts: posts.length,
        totalComments: comments.length,
        totalReports: reports.length,
        pendingReports: reports.filter(r => r.status === 'pending').length,
        resolvedReports: reports.filter(r => r.status === 'resolved').length,
        rejectedReports: reports.filter(r => r.status === 'rejected').length,
        todayPosts: posts.filter(p => p.date === new Date().toISOString().split('T')[0]).length,
        todayComments: comments.filter(c =>
            c.createdAt.split('T')[0] === new Date().toISOString().split('T')[0]
        ).length
    };

    res.json({ success: true, stats });
});

// ============= 에러 핸들러 =============

// Multer 에러 처리 미들웨어
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                success: false,
                message: '파일 크기가 너무 큽니다. 최대 10MB까지 업로드 가능합니다.'
            });
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({
                success: false,
                message: '파일 개수가 너무 많습니다. 최대 30개까지 업로드 가능합니다.'
            });
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
            return res.status(400).json({
                success: false,
                message: '예상치 못한 파일 필드입니다.'
            });
        }
        return res.status(400).json({
            success: false,
            message: '파일 업로드 중 오류가 발생했습니다: ' + error.message
        });
    }

    if (error.message && error.message.includes('허용되지 않는 파일 형식')) {
        return res.status(400).json({
            success: false,
            message: error.message
        });
    }

    // 기타 에러
    console.error('서버 오류:', error);
    res.status(500).json({
        success: false,
        message: '서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요.'
    });
});

// 404 에러 처리
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: '요청한 페이지를 찾을 수 없습니다.'
    });
});

// ============= 서버 시작 =============
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║     도래울베이스 서버 실행 중!        ║
╚════════════════════════════════════════╝

🌐 서버 주소: http://localhost:${PORT}
📁 데이터 저장 경로: ${DATA_DIR}
📤 업로드 경로: ${UPLOADS_DIR}

⚠️  주의사항:
1. .env 파일에 KAKAO_CLIENT_ID를 설정해주세요.
2. 리다이렉트 URI를 카카오 개발자 센터에 등록해주세요:
   ${KAKAO_CONFIG.REDIRECT_URI}

🚀 브라우저에서 http://localhost:${PORT} 접속
    `);
});
