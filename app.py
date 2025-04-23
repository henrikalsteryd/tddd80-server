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



load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///demo.db"
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

# Many-to-Many-tabell för att hantera followers (en följare följer en annan)
followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('following_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# Many-to-Many-tabell för likes
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

    followers = db.relationship(
        'User',
        secondary=followers,
        primaryjoin=id == followers.c.following_id,
        secondaryjoin=id == followers.c.follower_id,
        backref=db.backref('following', lazy='dynamic'),
        lazy='dynamic'
    )

    def __init__(self, username, password):
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def to_dict(self):
        return {'user': self.username, 'uid': self.id}

    # Funktioner kopplade till user-hantering
    # Retunera true/false baserat på om användare följer
    def is_following(self, user):
        return user in self.following

    # Lägg till så att en användare följer en annan
    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)

    # Ta bort så att en följare inte längre följer någon
    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)

    # Hantera liked_reviews
    liked_reviews = db.relationship(
            'Review',
            secondary=likes,
            backref=db.backref('liked_by', lazy='dynamic'),
            lazy='dynamic'
        )

    # Funktion för att gilla review
    def like_review(self, review):
        if not self.has_liked_review(review):
            self.liked_reviews.append(review)

    # Funktion för att ta bort sin like
    def unlike_review(self, review):
        if self.has_liked_review(review):
            self.liked_reviews.remove(review)

    # Funktion för att se om någon gillat en
    def has_liked_review(self, review):
        return review in self.liked_reviews


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    drink_name = db.Column(db.String(100), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    review_text = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=True)  # Lagrar sökvägen till bilden
    is_recipe = db.Column(db.Boolean, default=False, nullable=False)  # Gör det möjligt för användaren att skicka en post

    #Spara plats "city"
    location_city = db.Column(db.String(100), nullable=False)
    location_name = db.Column(db.String(100), nullable=False)

    # Som standard så är created_at den tiden som databasen sparar den
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


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
        print(data)  # Debug-print

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password are required'}), 400

        username = data['username']
        password = data['password']
        existing_user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': f'User {new_user.username} created', 'user_id': new_user.id}), 200

    except Exception as e:
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/user/login', methods=['POST'])
def user_login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password are required'}), 400

    username = data['username']
    password = data['password']
    u = User.query.filter_by(username=username).first()

    if u is None or not bcrypt.check_password_hash(u.password_hash, password):
        return jsonify({'error': 'No such user or wrong password'}), 400

    token = create_access_token(identity=u.username)
    return jsonify({'access_token': token}), 200


@app.route('/user/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt_identity()
    db.session.add(TokenBlocklist(jti=jti))
    db.session.commit()
    return jsonify({"message": "User successfully logged out"}), 200


# Discover/find user - handlers
@app.route('/discover', methods=['GET'])
@jwt_required()
def search():
    query = request.args.get('query', '')

    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    # Sök efter användare där username innehåller sökordet (case-insensitive)
    results = (
        User.query
        .filter(User.username.ilike(f"%{query}%"))
        .limit(25)
        .all()
    )

    return jsonify({
        "results": [
            {"user_id": user.id, "username": user.username}
            for user in results
        ]
    }), 200


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
    data = request.get_json()
    user_id = data.get("user_id")
    drink_name = data.get("drink_name")
    rating = data.get("rating")
    review_text = data.get("review_text")
    image_url = data.get("image_url")

    if not user_id or not drink_name or rating is None:
        return jsonify({"error": "Missing required fields (user_id, drink_name, rating)"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Skapa en ny review
    new_review = Review(
        user_id=user_id,
        drink_name=drink_name,
        rating=rating,
        review_text=review_text,
        image_url=image_url
    )

    db.session.add(new_review)
    db.session.commit()

    return jsonify({
        "message": "Review created successfully",
        "review": {
            "id": new_review.id,
            "user_id": new_review.user_id,
            "drink_name": new_review.drink_name,
            "rating": new_review.rating,
            "review_text": new_review.review_text,
            "image_url": new_review.image_url,
            "created_at": new_review.created_at.isoformat()
        }
    }), 201


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
@app.route('/review/get', methods=['POST'])
def get_review():
    data = request.get_json()
    review_id = data.get("review_id")

    if not review_id:
        return jsonify({"error": "Missing review_id"}), 400

    review = db.session.get(Review, review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Räkna antal likes
    like_count = db.session.execute(
        db.select(db.func.count()).select_from(likes).where(likes.c.review_id == review_id)
    ).scalar()

    return jsonify({
        "id": review.id,
        "user_id": review.user_id,
        "drink_name": review.drink_name,
        "rating": review.rating,
        "review_text": review.review_text,
        "image_url": review.image_url,
        "created_at": review.created_at.isoformat(),
        "likes": like_count
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

        image_url = request.host_url.rstrip('/') + f'/static/uploads/{filename}'
        return jsonify({'image_url': image_url}), 200

    return jsonify({'error': 'Invalid file type'}), 400


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
    db.create_all()

 # if __name__ == "__main__":
    # print(f"[DEBUG] Använder databas: {app.config['SQLALCHEMY_DATABASE_URI']}")
    # print("[DEBUG] Kör debug-mode")
    # app.debug = True
    # app.run(port=5089)
