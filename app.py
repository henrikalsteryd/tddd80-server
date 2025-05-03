from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from flask_jwt_extended import jwt_required, JWTManager
from flask_jwt_extended import create_access_token, get_jwt_identity
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
import datetime
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from flask import send_from_directory
from datetime import timedelta


load_dotenv()


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///demo.db"
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)
db = SQLAlchemy()
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

UPLOAD_FOLDER = '/tmp/uploads'  # Render tillåter bara /tmp för uppladdningar
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Skapa mappen om den inte finns
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# FOLLOWERS association table
followers_table = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('following_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# LIKES association table
likes = db.Table(
    'likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('review_id', db.Integer, db.ForeignKey('review.id'), primary_key=True)
)

class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column(nullable=False)
    user_description = db.Column(db.String(100), nullable=True)
    
    dark_mode = db.Column(db.Boolean, default=False, nullable=False)
    language = db.Column(db.String(2), default='en', nullable=False)
    profile_picture = db.Column(db.String(20), nullable=False)

    # Users this user is following
    following = db.relationship(
        'User',
        secondary=followers_table,
        primaryjoin=(followers_table.c.follower_id == id),
        secondaryjoin=(followers_table.c.following_id == id),
        backref=db.backref('followers', lazy='dynamic'),
        lazy='dynamic'
    )

    liked_reviews = db.relationship(
        'Review',
        secondary=likes,
        backref=db.backref('liked_by', lazy='dynamic'),
        lazy='dynamic'
    )

    def __init__(self, username, password, language, dark_mode, profile_picture):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.language = language
        self.dark_mode = dark_mode
        self.profile_picture=profile_picture

    def is_following(self, user):
        return self.following.filter(followers_table.c.following_id == user.id).count() > 0

    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)

    def has_liked_review(self, review):
        return self.liked_reviews.filter(likes.c.review_id == review.id).count() > 0

    def like_review(self, review):
        if not self.has_liked_review(review):
            self.liked_reviews.append(review)

    def unlike_review(self, review):
        if self.has_liked_review(review):
            self.liked_reviews.remove(review)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    drink_name = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    review_text = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True)  # Lagrar sökvägen till bilden
    is_recipe = db.Column(db.Boolean, default=False, nullable=False)  # Gör det möjligt för användaren att skicka en post

    #Spara plats "city"
    location_city = db.Column(db.String(100), nullable=True)
    location_name = db.Column(db.String(100), nullable=True)

    # Som standard så är created_at den tiden som databasen sparar den
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Klass för notiser.
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))


def create_notification(user_id, message):
    # Hämta användaren från databasen
    # Det är bara relevant att spara 20 notifikationer, därför raderar vi om det är över 30.
    user = db.session.get(User, user_id)
    
    if user:
        # Skapa en ny notis
        new_notification = Notification(user_id=user_id, message=message)
        
        # Lägg till notisen i databasen
        db.session.add(new_notification)
        db.session.commit()
        
        # Kolla om användaren har fler än 20 notiser
        notifications_count = Notification.query.filter_by(user_id=user_id).count()
        if notifications_count > 20:
            # Ta bort den äldsta notisen
            oldest_notification = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at).first()
            db.session.delete(oldest_notification)
            db.session.commit()

# Klass för kommentarer
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref='comments')
    review = db.relationship('Review', backref=db.backref('comments', lazy='dynamic'))


class TokenBlocklist(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(unique=True, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(nullable=False, default=datetime.datetime.utcnow)


# Login/Logut/Create user - handlers 
@app.route('/user', methods=['POST'])
def create_user():
    try:
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password are required'}), 400

        # Normalize username to lowercase så att flera användare inte kan ha samma namn.
        username = data['username'].strip().lower()
        password = data['password']
        
        # Hämta språk och dark_mode, använd default om de inte finns
        language = data.get('language', 'en')  # Standardvärde 'en' om inget anges
        dark_mode = data.get('dark_mode', False)  # Standardvärde False om inget anges

        # Hämta profile picture som skickas med
        profile_picture = data.get('profile picture', 'profile_1')  # Standardvärde False om inget anges

        # Kontrollera om användarnamnet redan finns (case-insensitive)
        existing_user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400

        # Skapa den nya användaren
        new_user = User(username=username, password=password, language=language, dark_mode=dark_mode, profile_picture=profile_picture)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': f'User {new_user.username} created', 'user_id': new_user.id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/user/login', methods=['POST'])
def user_login():
    data = request.get_json()
    
    # Kontrollera om username och password är angivna
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']
    
    # Hämta användaren från databasen baserat på användarnamn
    u = User.query.filter_by(username=username).first()

    # Kontrollera om användaren inte finns eller om lösenordet är felaktigt
    if u is None or not bcrypt.check_password_hash(u.password_hash, password):
        return jsonify({'error': 'No such user or wrong password'}), 400

    # Skapa en access token för användaren
    token = create_access_token(identity=u.username)

    # Skicka tillbaka token, användar-ID och dark mode-inställning
    return jsonify({
        'access_token': token, 
        'user_id': u.id, 
        'dark_mode': u.dark_mode,  # Lägg till dark_mode-inställningen här
        'language': u.language  # Lägg till dark_mode-inställningen här
    }), 200


@app.route('/user/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt_identity()

    # Kontrollera om jti redan finns i token_blocklist
    existing_token = TokenBlocklist.query.filter_by(jti=jti).first()

    if existing_token:
        # Om tokenet redan är blockerad, returnera ett meddelande, men godkän utloggningen.
        return jsonify({"message": "User already logged out"}), 200 

    # Lägg till tokenet i blocklistan
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()

    return jsonify({"message": "User successfully logged out"}), 200


@app.route('/user', methods=['GET'])
@jwt_required()
def get_user_profile():
 
    raw_username = request.args.get('username')
    raw_viewer = request.args.get('viewer_username')

    if not raw_username:
        return jsonify({"error": "Missing username"}), 400

    username = raw_username.strip().lower()
    viewer_username = raw_viewer.strip().lower() if raw_viewer else None
   
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    followers_count = user.followers.count()
    following_count = user.following.count()
    reviews_count = Review.query.filter_by(user_id=user.id, is_recipe=False).count()
    recipes_count = Review.query.filter_by(user_id=user.id, is_recipe=True).count()

    is_following = False
    is_followed_by = False
    is_friend = False

    if viewer_username:
        viewer = User.query.filter_by(username=viewer_username).first()
        if viewer:
            is_following = viewer.is_following(user)
            is_followed_by = user.is_following(viewer)
            is_friend = is_following and is_followed_by

    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "user_description": user.user_description,
        "followers_count": followers_count,
        "following_count": following_count,
        "reviews_count": reviews_count,
        "recipes_count": recipes_count,
        "is_following": is_following,
        "is_followed_by": is_followed_by,
        "is_friend": is_friend
    }), 200


@app.route('/user/reviews', methods=['GET'])
@jwt_required()
def get_user_reviews():
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    reviews = Review.query.filter_by(user_id=user_id).all()

    reviews_data = [
        {
            "review_id": review.id,
            "drink_name": review.drink_name,
            "image_url": review.image_url
        }
        for review in reviews
    ]

    return jsonify({"reviews": reviews_data}), 200


# Discover/find user - handlers
@app.route('/discover', methods=['GET'])
@jwt_required()
def search():
    query = request.args.get('query', '').strip()
    category = request.args.get('category', 'Profile').strip()
    current_user = get_jwt_identity()

    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    if category == 'Profile':
        # Uteslut den aktuella användaren
        results = (
            User.query
            .filter(User.username.ilike(f"%{query}%"))
            .filter(User.username != current_user)
            .limit(25)
            .all()
        )
        return jsonify({
            "results": [
                {"user_id": user.id, "username": user.username}
                for user in results
            ]
        }), 200

    elif category in ['Reviews', 'Recipes']:
        is_recipe_value = (category == 'Recipes')

        reviews = (
            Review.query
            .filter(Review.drink_name.ilike(f"%{query}%"))
            .filter(Review.is_recipe == is_recipe_value)
            .limit(25)
            .all()
        )

        return jsonify({
            "results": [
                {
                    "review_id": r.id,
                    "drink_name": r.drink_name,
                    "username": User.query.get(r.user_id).username,
                    "image_url": r.image_url
                }
                for r in reviews
            ]
        }), 200

    else:
        return jsonify({"error": "Invalid category"}), 400


# Following/Unfollowing - handlers
@app.route('/user/follow', methods=['POST'])
@jwt_required()
def follow():
    data = request.get_json()
    follower_id = data.get("follower_id")
    following_id = data.get("following_id")

    if not follower_id or not following_id:
        return jsonify({"error": "Missing follower_id or following_id"}), 400
    if follower_id == following_id:
        return jsonify({"error": "You cannot follow yourself"}), 400

    follower = db.session.get(User, follower_id)
    following = db.session.get(User, following_id)
    if not follower or not following:
        return jsonify({"error": "User not found"}), 404
    if follower.is_following(following):
        return jsonify({"message": "Already following"}), 400

    follower.follow(following)
    db.session.commit()
    create_notification(following.id, f"{follower.username} just started following you")
    return jsonify({"message": f"{follower.username} is now following {following.username}"}), 200


@app.route('/user/unfollow', methods=['POST'])
@jwt_required()
def unfollow():
    data = request.get_json()
    follower_id = data.get("follower_id")
    following_id = data.get("following_id")

    if not follower_id or not following_id:
        return jsonify({"error": "Missing follower_id or following_id"}), 400

    follower = db.session.get(User, follower_id)
    following = db.session.get(User, following_id)
    if not follower or not following:
        return jsonify({"error": "User not found"}), 404
    if not follower.is_following(following):
        return jsonify({"message": "Not following this user"}), 400

    follower.unfollow(following)
    db.session.commit()
    return jsonify({"message": f"{follower.username} has unfollowed {following.username}"}), 200


# Review POST/GET - handlers
@app.route('/review/create', methods=['POST'])
@jwt_required()
def create_review():
    data = request.get_json() or {}

    # Ta emot alla fält, med default-värden där det är lämpligt
    user_id = data.get("user_id")
    drink_name = data.get("drink_name")
    rating = data.get("rating")
    review_text = data.get("review_text")
    image_url = data.get("image_url")
    is_recipe = data.get("is_recipe", False)
    location_city = data.get("location_city")       # None om inte skickas
    location_name = data.get("location_name")       # None om inte skickas

    # Kontroll: obligatoriska fält
    if not user_id or not drink_name or rating is None:
        return jsonify({
            "error": "Missing required fields (user_id, drink_name, rating)"
        }), 400

    # Hämta användaren
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Skapa och spara review/recipe
    new_review = Review(
        user_id=user_id,
        drink_name=drink_name,
        rating=rating,
        review_text=review_text,
        image_url=image_url,
        is_recipe=bool(is_recipe),
        location_city=location_city,
        location_name=location_name
    )

    db.session.add(new_review)
    db.session.commit()

    # Returnera det nya objektet – inklusive de nya fälten
    return jsonify({
        "message": "Review created successfully",
        "review": {
            "id": new_review.id,
            "user_id": new_review.user_id,
            "drink_name": new_review.drink_name,
            "rating": new_review.rating,
            "review_text": new_review.review_text,
            "image_url": new_review.image_url,
            "is_recipe": new_review.is_recipe,
            "location_city": new_review.location_city,
            "location_name": new_review.location_name,
            "created_at": new_review.created_at.isoformat()
        }
    }), 200



@app.route('/review/delete', methods=['DELETE'])
@jwt_required()
def delete_review():
    data = request.get_json()
    user_id = data.get("user_id")
    review_id = data.get("review_id")

    if not user_id or not review_id:
        return jsonify({"error": "Missing user_id or review_id"}), 400

    user = db.session.get(User, user_id)
    review = db.session.get(Review, review_id)

    if not user or not review:
        return jsonify({"error": "User or review not found"}), 404

    if review.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403  # Användaren får bara ta bort sina egna reviews

    db.session.delete(review)
    db.session.commit()

    return jsonify({"message": f"Review {review.id} deleted successfully"}), 200


# Get a specific post
@jwt_required()
@app.route('/review/get', methods=['POST'])
def get_review():
    data = request.get_json()
    review_id = data.get("review_id")
    user_id = data.get("user_id")  # Vi får user_id från requesten istället för från JWT.

    if not review_id or not user_id:
        return jsonify({"error": "Missing review_id or user_id"}), 400

    review = db.session.get(Review, review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Hämta användarnamnet för recensionen
    user = db.session.get(User, review.user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Hämta den användare som skickades med och kontrollera om den har gillat recensionen
    target_user = db.session.get(User, user_id)

    if not target_user:
        return jsonify({"error": "Target user not found"}), 404

    # Kontrollera om den angivna användaren har gillat denna recension
    has_liked = target_user.has_liked_review(review)

    # Räkna antal likes
    like_count = db.session.execute(
        db.select(db.func.count()).select_from(likes).where(likes.c.review_id == review_id)
    ).scalar()

    return jsonify({
        "id": review.id,
        "user_id": review.user_id,
        "username": user.username,  # Lägg till användarnamnet här
        "drink_name": review.drink_name,
        "rating": review.rating,
        "review_text": review.review_text,
        "image_url": review.image_url,
        "created_at": review.created_at.isoformat(),
        "likes": like_count,
        "has_liked": has_liked  # Lägg till om användaren har gillat recensionen
    }), 200


# Comment ADD/REMOVE/GET all (för en specifik review) - handlers
@app.route('/review/comment', methods=['POST'])
@jwt_required()
def add_comment():
    data = request.get_json()
    user_id = data.get("user_id")
    review_id = data.get("review_id")
    comment_text = data.get("comment_text")

    if not user_id or not review_id or not comment_text:
        return jsonify({"error": "Missing user_id, review_id, or comment_text"}), 400

    user = db.session.get(User, user_id)
    review = db.session.get(Review, review_id)

    if not user or not review:
        return jsonify({"error": "User or review not found"}), 404

    new_comment = Comment(user_id=user_id, review_id=review_id, comment_text=comment_text)
    db.session.add(new_comment)
    db.session.commit()

    # Skapa en notis för användaren som har reviewn.
    create_notification(review.user_id, f"{user.username} commented '{comment_text}' on your review.")

    return jsonify({
        "message": "Comment added successfully",
        "comment": {
            "id": new_comment.id,
            "user_id": new_comment.user_id,
            "review_id": new_comment.review_id,
            "comment_text": new_comment.comment_text,
            "created_at": new_comment.created_at.isoformat()
        }
    }), 201


# Ta bort en kommentar som finns
@app.route('/review/comment/delete', methods=['DELETE'])
@jwt_required()
def delete_comment():
    data = request.get_json()
    user_id = data.get("user_id")
    comment_id = data.get("comment_id")

    if not user_id or not comment_id:
        return jsonify({"error": "Missing user_id or comment_id"}), 400

    user = db.session.get(User, user_id)
    comment = db.session.get(Comment, comment_id)

    if not user or not comment:
        return jsonify({"error": "User or comment not found"}), 404

    # Kontrollera att användaren äger kommentaren innan borttagning
    if comment.user_id != user.id:
        return jsonify({"error": "Unauthorized"}), 403  

    db.session.delete(comment)
    db.session.commit()

    return jsonify({"message": f"Comment {comment.id} deleted successfully"}), 200


# Hämta alla kommentarer för en review
@app.route('/review/comments', methods=['GET'])
@jwt_required()
def get_comments():
    review_id = request.args.get("review_id")

    if not review_id:
        return jsonify({"error": "Missing review_id"}), 400

    review = db.session.get(Review, review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    comments = [
        {
            "id": comment.id,
            "user_id": comment.user_id,
            "username": comment.user.username,  
            "comment_text": comment.comment_text,
            "created_at": comment.created_at.isoformat()
        }
        for comment in review.comments
    ]

    return jsonify({"review_id": review_id, "comments": comments}), 200


# Review LIKE/UNLIKE - handlers
@app.route('/review/like', methods=['POST'])
@jwt_required()
def like_review():
    data = request.get_json()
    user_id = data.get("user_id")
    review_id = data.get("review_id")

    if not user_id or not review_id:
        return jsonify({"error": "Missing user_id or review_id"}), 400

    user = db.session.get(User, user_id)
    review = db.session.get(Review, review_id)

    if not user or not review:
        return jsonify({"error": "User or review not found"}), 404

    if user.has_liked_review(review):
        return jsonify({"message": "Review already liked"}), 400

    user.like_review(review)
    db.session.commit()

    # Skapa en notis för användaren som har reviewn.
    create_notification(review.user_id, f"{user.username} liked your review '{review.drink_name}'")

    return jsonify({"message": f"Review {review.id} liked by {user.username}"}), 200


@app.route('/review/unlike', methods=['POST'])
@jwt_required()
def unlike_review():
    data = request.get_json()
    user_id = data.get("user_id")
    review_id = data.get("review_id")

    if not user_id or not review_id:
        return jsonify({"error": "Missing user_id or review_id"}), 400

    user = db.session.get(User, user_id)
    review = db.session.get(Review, review_id)

    if not user or not review:
        return jsonify({"error": "User or review not found"}), 404

    if not user.has_liked_review(review):
        return jsonify({"message": "Review not liked yet"}), 400

    user.unlike_review(review)
    db.session.commit()

    return jsonify({"message": f"Review {review.id} unliked by {user.username}"}), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image provided'}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        image_url = request.host_url.rstrip('/') + f'/uploads/{filename}'
        return jsonify({'image_url': image_url}), 200

    return jsonify({'error': 'Invalid file type'}), 400

# Notifcations handler - GET
@app.route('/user/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "Missing user_id"}), 400

    # Hämta de senaste 20 notiserna, sorterade efter skapelsedatum (nyaste först)
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(20).all()

    notifications_data = [
        {
            "id": notification.id,
            "message": notification.message,
            "created_at": notification.created_at.isoformat()
        }
        for notification in notifications
    ]

    return jsonify({"notifications": notifications_data}), 200


# Feed handler - GET
@app.route('/user/recent_posts', methods=['GET'])
@jwt_required()
def get_recent_posts():
    # Hämta user_id från query-parametern
    user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    # Hämta användaren från user_id
    current_user = User.query.get(user_id)

    if not current_user:
        return jsonify({"error": "User not found"}), 404

    # Hämta alla användare som den aktuella användaren följer
    followed_users = current_user.following.all()

    all_posts = []
    
    # Hämta alla posts för de användare som följs
    for user in followed_users:
        posts = Review.query.filter_by(user_id=user.id).all()  # Hämta recensioner (posts) från följda användare
        all_posts.extend(posts)

    # Sortera inläggen på tidsstämpel (nyast först)
    sorted_posts = sorted(all_posts, key=lambda post: post.created_at, reverse=True)

    # Ta de 30 senaste inläggen
    recent_posts = sorted_posts[:30]

    # Förbered datat som ska returneras
    posts_data = []
    for post in recent_posts:
        # Hämta användarnamn för posten
        user = User.query.get(post.user_id)
        if user:
            # Räkna likes
            like_count = db.session.execute(
                db.select(db.func.count()).select_from(likes).where(likes.c.review_id == post.id)
            ).scalar()

            # Räkna kommentarer
            comment_count = db.session.execute(
                db.select(db.func.count()).select_from(Comment).where(Comment.review_id == post.id)
            ).scalar()

            posts_data.append({
                "post_id": post.id,
                "username": user.username,
                "drink_name": post.drink_name,
                "rating": post.rating,
                "review_text": post.review_text,
                "image_url": post.image_url,
                "created_at": post.created_at.isoformat(),
                "is_recipe": post.is_recipe,
                "like_count": like_count,
                "comment_count": comment_count
            })

    # Skicka tillbaka data med user_id som query-parameter
    return jsonify({
        "user_id": user_id,
        "recent_posts": posts_data
    }), 200

# Prefrences POST/GET - Användarens språk, dark_mode etc
@app.route('/user/prefrences', methods=['GET'])
@jwt_required()
def get_user_prefrences():
    username = request.args.get('username')  # den profil vi tittar på

    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "dark_mode": user.dark_mode,
        "language": user.language,
        "user_description": user.user_description,
    }), 200


@app.route('/user/preferences', methods=['POST'])
@jwt_required()
def set_user_preferences():
    data = request.get_json()

    username = data.get('username')
    dark_mode = data.get('dark_mode')
    language = data.get('language')
    user_description = data.get('user_description')

    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if dark_mode is not None:
        user.dark_mode = dark_mode
    if language is not None:
        user.language = language
    if user_description is not None:
        user.user_description = user_description

    db.session.commit()

    return jsonify({"message": "Preferences updated successfully"}), 200

# Blocklist loader
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.execute(db.select(TokenBlocklist).filter_by(jti=jti)).scalar_one_or_none()
    return token is not None


# ERROR HANDLERS
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Missing arguments"}), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Route not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"error": "Server error"}), 500


with app.app_context():
    db.drop_all()  # Radera alla tabeller
    db.create_all()  # Skapa alla tabeller på nytt

 # if __name__ == "__main__":
    # print(f"[DEBUG] Använder databas: {app.config['SQLALCHEMY_DATABASE_URI']}")
    # print("[DEBUG] Kör debug-mode")
    # app.debug = True
    # app.run(port=5089)
