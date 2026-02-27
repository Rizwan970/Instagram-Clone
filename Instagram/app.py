from PIL import Image
from uuid import uuid4
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import secrets
from functools import wraps
from sqlalchemy import inspect as sa_inspect

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'instagram_super_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instagram.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 1000MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)
with app.app_context():
    print("📌 DB FILE USED BY FLASK:", db.engine.url.database)

# Database Models
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reason = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    post = db.relationship('Post')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caption = db.Column(db.String(500))
    image = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship(
        'User',
        back_populates='posts'
    )

    comments = db.relationship('Comment', backref='post', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='post', cascade='all, delete-orphan')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)   # 🔴 THIS COLUMN IS MISSING IN DB
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship('User', backref='comments')

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_like'),
    )

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (
        db.UniqueConstraint('follower_id', 'following_id', name='unique_follow'),
    )
    
class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    image = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='tweets')
    likes = db.relationship('TweetLike', cascade='all, delete-orphan')
    comments = db.relationship('TweetComment', cascade='all, delete-orphan')

class TweetLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweet.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    __table_args__ = (
        db.UniqueConstraint('tweet_id', 'user_id', name='unique_tweet_like'),
    )

class TweetComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tweet_id = db.Column(db.Integer, db.ForeignKey('tweet.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500))
    profile_pic = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)

    posts = db.relationship(
        'Post',
        back_populates='author',
        cascade='all, delete-orphan'
    )
    @property
    def followers_count(self):
        return Follow.query.filter_by(following_id=self.id).count()

    @property
    def following_count(self):
        return Follow.query.filter_by(follower_id=self.id).count()

    @property
    def posts_count(self):
        return Post.query.filter_by(user_id=self.id).count()


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))

@app.route('/report/<int:post_id>', methods=['POST'])
def report_post(post_id):
    data = request.json
    reason = data.get('reason')

    report = Report(
        user_id=session['user_id'],
        post_id=post_id,
        reason=reason
    )
    db.session.add(report)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()

        admin = User.query.filter_by(
            username=data['username'],
            is_admin=True
        ).first()

        if admin and check_password_hash(admin.password, data['password']):
            session.clear()
            session['admin_id'] = admin.id
            session['is_admin'] = True
            session['admin'] = True
            return jsonify({'success': True})

        return jsonify({'success': False}), 401

    return render_template('admin/admin_login.html')

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if User.query.filter_by(is_admin=True).first():
        return "Admin already exists", 403

    if request.method == 'POST':
        data = request.get_json()

        user = User(
            username=data['username'],
            email=data['email'],
            password=generate_password_hash(data['password']),
            is_admin=True
        )

        db.session.add(user)
        db.session.commit()

        return jsonify({'success': True})

    return render_template('admin/admin_register.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    data = {
        'users': User.query.count(),
        'posts': Post.query.count(),
        'likes': Like.query.count(),
        'reports': Report.query.count()
    }
    return render_template('admin/dashboard.html', data=data)


@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/ban-user/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    data = {
        'total_users': User.query.count(),
        'total_posts': Post.query.count(),
        'total_comments': Comment.query.count(),
        'total_likes': Like.query.count(),
        'total_reports': Report.query.count()
    }
    return render_template('admin_analytics.html', data=data)
@app.route('/register', methods=['GET', 'POST'])
def register() :
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields required'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400 
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        hashed_pwd = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_pwd)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Registration successful'}), 201 
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):

    # 🚫 STEP 7 — BAN CHECK
            if user.is_banned:
                return jsonify({
                    'success': False,
                    'message': '🚫 Your account has been banned by admin'
                }), 403
            session['user_id'] = user.id
            session['username'] = user.username
            return jsonify({'success': True, 'message': 'Login successful'}), 200
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/feed')
def feed():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # 🚫 Optional: block banned users completely
    if user.is_banned:
        session.clear()
        return redirect(url_for('login'))
    posts = Post.query.order_by(Post.created_at.desc()).all()
    tweets = Tweet.query.order_by(Tweet.created_at.desc()).limit(20).all()
    return render_template(
        'feed.html',
        posts=posts,
        tweets=tweets,
        user=user
    )

@app.route('/profile/<username>')
def profile(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('feed'))
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    current_user = User.query.get(session['user_id'])
    # compute whether the current session user is following the profile user
    is_following = False
    if current_user and Follow.query.filter_by(follower_id=current_user.id, following_id=user.id).first():
        is_following = True

    return render_template('profile.html', profile_user=user, posts=posts, current_user=current_user, is_following=is_following)
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/profile-picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    file = request.files.get('image')
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid image'}), 400

    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"profile_{uuid4().hex}.{ext}"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    img = Image.open(file).convert("RGB")
    img = img.resize((400, 400), Image.LANCZOS)
    img.save(path, "JPEG", quality=85)

    user = User.query.get(session['user_id'])

    # delete old pic if not default
    if user.profile_pic != 'default.jpg':
        old = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
        if os.path.exists(old):
            os.remove(old)

    user.profile_pic = filename
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'image' not in request.files:
        return jsonify({'error': 'No image selected'}), 400

    file = request.files['image']
    caption = request.form.get('caption')
    location = request.form.get('location')

    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    # Unique & safe filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    filename = f"{uuid4().hex}.{ext}"
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # 🔥 Resize & compress (PERMANENT FIX)
    img = Image.open(file)
    img = img.convert("RGB")

    MAX_WIDTH = 1080
    if img.width > MAX_WIDTH:
        ratio = MAX_WIDTH / img.width
        new_height = int(img.height * ratio)
        img = img.resize((MAX_WIDTH, new_height), Image.LANCZOS)

    img.save(upload_path, "JPEG", quality=85, optimize=True)

    post = Post(
        image=filename,
        caption=caption,
        location=location,
        user_id=session['user_id']
    )

    db.session.add(post)
    db.session.commit()

    return jsonify({'success': True}), 201

@app.route('/api/post/<int:post_id>')
def get_post(post_id):
    post = Post.query.get_or_404(post_id)
    return jsonify({
        "id": post.id,
        "image": post.image.split('/')[-1],
        "caption": post.caption,
        "username": post.user.username,
        "profile_pic": post.user.profile_pic.split('/')[-1] if post.user.profile_pic else 'default.jpg',
        "likes": len(post.likes),
        "comments": [
            {
                "username": c.user.username,
                "text": c.text
            } for c in post.comments
        ]
    })

@app.route('/api/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401

    post = Post.query.get_or_404(post_id)

    existing_like = Like.query.filter_by(
        user_id=session['user_id'],
        post_id=post.id
    ).first()

    if existing_like:
        db.session.delete(existing_like)
        action = "unliked"
    else:
        new_like = Like(
            user_id=session['user_id'],
            post_id=post.id
        )
        db.session.add(new_like)
        action = "liked"

    db.session.commit()

    likes_count = Like.query.filter_by(post_id=post.id).count()

    return jsonify({
        "success": True,
        "action": action,
        "likes": likes_count
    })

@app.route('/api/comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'user_id' not in session:
        return jsonify(success=False), 401

    text = request.json.get('text')
    if not text:
        return jsonify(success=False)

    comment = Comment(
        text=text,
        user_id=session['user_id'],
        post_id=post_id
    )

    db.session.add(comment)
    db.session.commit()

    return jsonify(
        success=True,
        username=session['username'],
        text=text
    )

@app.route('/api/follow/<int:user_id>', methods=['POST'])
def follow_user(user_id):
    if 'user_id' not in session:
        return jsonify({'success': False}), 401

    current_user_id = session['user_id']

    if current_user_id == user_id:
        return jsonify({'success': False}), 400

    follow = Follow.query.filter_by(
        follower_id=current_user_id,
        following_id=user_id
    ).first()

    if follow:
        db.session.delete(follow)
        action = 'unfollowed'
    else:
        follow = Follow(
            follower_id=current_user_id,
            following_id=user_id
        )
        db.session.add(follow)
        action = 'followed'
        if action == 'followed':
            note = Notification(
                user_id=user_id,
                message=f"{session['username']} started following you"
            )
            db.session.add(note)

    db.session.commit()

    return jsonify({
        'success': True,
        'action': action,
        'followers': Follow.query.filter_by(following_id=user_id).count()
    })
    
@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect('/login')

    notes = Notification.query.filter_by(
        user_id=session['user_id']
    ).order_by(Notification.created_at.desc()).all()

    return render_template('notifications.html', notes=notes)
 
@app.route('/admin/delete-post/<int:post_id>', methods=['POST'])
@admin_required
def admin_delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # delete image
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image)
    if os.path.exists(image_path):
        os.remove(image_path)

    # delete reports
    Report.query.filter_by(post_id=post.id).delete()

    db.session.delete(post)
    db.session.commit()

    return jsonify({'success': True})


@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/admin/login')

@app.route('/admin/reports')
@admin_required
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@app.route('/admin/delete-reported-post/<int:post_id>', methods=['POST'])
@admin_required
def delete_reported_post(post_id):
    post = Post.query.get_or_404(post_id)

    # delete image file
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], post.image)
    if os.path.exists(image_path):
        os.remove(image_path)

    # delete related reports
    Report.query.filter_by(post_id=post.id).delete()

    db.session.delete(post)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/tweet', methods=['POST'])
def create_tweet():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])
    if getattr(user, 'is_banned', False):
        return jsonify({'error': 'Banned'}), 403

    content = request.form.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Empty tweet'}), 400

    filename = None
    file = request.files.get('image')
    if file and allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[1].lower()
        filename = f"{uuid4().hex}.{ext}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    tweet = Tweet(
        content=content,
        image=filename,
        user_id=session['user_id']
    )
    db.session.add(tweet)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/api/tweet/like/<int:tweet_id>', methods=['POST'])
def like_tweet(tweet_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    like = TweetLike.query.filter_by(
        tweet_id=tweet_id,
        user_id=session['user_id']
    ).first()

    if like:
        db.session.delete(like)
    else:
        db.session.add(TweetLike(tweet_id=tweet_id, user_id=session['user_id']))

    db.session.commit()
    count = TweetLike.query.filter_by(tweet_id=tweet_id).count()
    return jsonify({'success': True, 'likes': count})

@app.route('/api/tweet/comment/<int:tweet_id>', methods=['POST'])
def comment_tweet(tweet_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Empty'}), 400

    comment = TweetComment(
        tweet_id=tweet_id,
        user_id=session['user_id'],
        content=content
    )
    db.session.add(comment)
    db.session.commit()

    return jsonify({'success': True})

@app.route('/tweet/<int:tweet_id>')
def view_tweet(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    return render_template('tweet_view.html', tweet=tweet)

@app.route('/admin/delete-tweet/<int:tweet_id>', methods=['POST'])
@admin_required
def admin_delete_tweet(tweet_id):
    tweet = Tweet.query.get_or_404(tweet_id)
    if tweet.image:
        image = os.path.join(app.config['UPLOAD_FOLDER'], tweet.image)
        if os.path.exists(image):
            os.remove(image)
    db.session.delete(tweet)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = User.query.get(session['user_id'])

    # delete profile pic
    if user.profile_pic != 'default.jpg':
        path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
        if os.path.exists(path):
            os.remove(path)

    db.session.delete(user)
    db.session.commit()
    session.clear()

    return jsonify({'success': True})

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/explore')
def explore():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    posts = Post.query.order_by(Post.created_at.desc()).limit(30).all()
    return render_template('explore.html', current_user=current_user, posts=posts)

@app.route('/api/search-users')
def search_users():
    if 'user_id' not in session:
        return jsonify([]), 401
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    users = User.query.filter(
        User.username.ilike(f'%{q}%'),
        User.id != session['user_id']
    ).limit(10).all()
    return jsonify([{
        'username': u.username,
        'profile_pic': u.profile_pic or 'default.jpg',
        'bio': u.bio or ''
    } for u in users])

@app.route('/admin/unban-user/<int:user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/posts')
@admin_required
def admin_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', posts=posts)

@app.route('/admin/banned')
@admin_required
def admin_banned():
    users = User.query.filter_by(is_banned=True).all()
    return render_template('admin/banned.html', users=users)

@app.route('/admin/dismiss-report/<int:report_id>', methods=['POST'])
@admin_required
def dismiss_report(report_id):
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/settings')
@admin_required
def admin_settings():
    return render_template('admin/settings.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(
        host='127.0.0.1',
        port=5000,
        debug=True,
        use_reloader=True
    )