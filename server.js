const express = require('express');
const session = require('express-session');
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
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// 디렉토리 생성
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// 초기 데이터 파일 생성
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(POSTS_FILE)) {
    // 기존 샘플 게시글 데이터 추가
    const samplePosts = require('./sample-posts.json');
    fs.writeFileSync(POSTS_FILE, JSON.stringify(samplePosts, null, 2));
}
if (!fs.existsSync(COMMENTS_FILE)) fs.writeFileSync(COMMENTS_FILE, '[]');
if (!fs.existsSync(LIKES_FILE)) fs.writeFileSync(LIKES_FILE, '{"posts": {}, "comments": {}}');

// 미들웨어 설정
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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

// 세션 설정
app.use(session({
    secret: process.env.SESSION_SECRET || 'doraeul-base-secret-key-2025',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: IS_PRODUCTION, // 프로덕션에서는 HTTPS 필수
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24시간
        sameSite: IS_PRODUCTION ? 'strict' : 'lax'
    }
}));

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
    CLIENT_ID: process.env.KAKAO_CLIENT_ID || '36fe6a8e7d85bfd61e9d474df2dbda16',
    REDIRECT_URI: process.env.KAKAO_REDIRECT_URI || `http://localhost:${PORT}/auth/kakao/callback`,
    CLIENT_SECRET: process.env.KAKAO_CLIENT_SECRET || ''
};

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
            return res.redirect('/register');
        } else {
            // 기존 회원 - 로그인 처리
            req.session.user = user;
            res.redirect('/');
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
        return res.status(400).json({ success: false, message: '세션이 만료되었습니다.' });
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

    res.json({ success: true, user: newUser });
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
    res.json({ success: true, posts });
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

    const { category, title, content, captchaToken } = req.body;

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
        comments: 0
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

    const { title, content, category } = req.body;
    const posts = readJSON(POSTS_FILE);
    const postIndex = posts.findIndex(p => p.id === parseInt(req.params.id));

    if (postIndex === -1) {
        return res.status(404).json({ success: false, message: '게시글을 찾을 수 없습니다.' });
    }

    const post = posts[postIndex];

    if (post.authorId !== req.session.user.id) {
        return res.status(403).json({ success: false, message: '권한이 없습니다.' });
    }

    if (title) post.title = title;
    if (content) post.content = content;
    if (category) {
        post.category = category;
        const categoryNames = {'notice': '공지', 'info': '정보', 'question': '질문', 'free': '자유'};
        post.categoryName = categoryNames[category];
    }

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
1. 카카오 개발자 센터에서 REST API 키를 발급받아
   KAKAO_CONFIG.CLIENT_ID에 입력해주세요.
2. 리다이렉트 URI를 카카오 개발자 센터에 등록해주세요:
   http://localhost:${PORT}/auth/kakao/callback

🚀 브라우저에서 http://localhost:${PORT}/doraeul-base.html 접속
    `);
});
