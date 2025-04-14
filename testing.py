import pytest
import server
import random
import string

@pytest.fixture()
def app():
    app = server.app
    app.config.update({"TESTING": True})
    yield app  # Ger tillbaka appen till testerna

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

# Funktion för att generera ett slumpmässigt användarnamn och lösenord
def generate_random_credentials():
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return username, password

# Test: Skapa en användare
def test_create_user(client):
    username, password = generate_random_credentials()
    response = client.post("/user", json={"username": username, "password": password})
    assert response.status_code == 200

# Test: Logga in som en användare
def test_user_login(client):
    username, password = generate_random_credentials()
    
    # Skapa användaren först
    client.post("/user", json={"username": username, "password": password})
    
    # Logga in
    response = client.post("/user/login", json={"username": username, "password": password})
    assert response.status_code == 200

    data = response.get_json()
    assert "access_token" in data

# Testa att logga in, sedan logga ut, och sedan att använda samma token igen
def test_user_logout(client):
    username, password = generate_random_credentials()
    
    # Skapa användaren
    client.post("/user", json={"username": username, "password": password})
    
    # Logga in
    login_response = client.post("/user/login", json={"username": username, "password": password})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]

    # Logga ut
    logout_response = client.post("/user/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_response.status_code == 200

# Test: Användare 1 följer och sedan avföljer användare 2
def test_user_follow_unfollow(client):
    # Skapa två användare
    username1, password1 = generate_random_credentials()
    username2, password2 = generate_random_credentials()
    
    response1 = client.post("/user", json={"username": username1, "password": password1})
    response2 = client.post("/user", json={"username": username2, "password": password2})
    
    assert response1.status_code == 200
    assert response2.status_code == 200
    
    # Logga in användare 1 och hämta token
    login_response = client.post("/user/login", json={"username": username1, "password": password1})
    assert login_response.status_code == 200
    token = login_response.json["access_token"]
    
    # Hämta användar-ID för båda användarna
    user1_id = response1.json["user_id"]
    user2_id = response2.json["user_id"]
    
    # Användare 1 följer användare 2
    follow_response = client.post("/user/follow", 
                                  json={"follower_id": user1_id, "following_id": user2_id},
                                  headers={"Authorization": f"Bearer {token}"})
    
    assert follow_response.status_code == 200
    assert "is now following" in follow_response.json["message"]
    
    # Användare 1 avföljer användare 2
    unfollow_response = client.post("/user/unfollow",
                                    json={"follower_id": user1_id, "following_id": user2_id},
                                    headers={"Authorization": f"Bearer {token}"})

    assert unfollow_response.status_code == 200
    assert "has unfollowed" in unfollow_response.json["message"]

# Testa skapa en review
def test_create_review(client):
    # Skapa en testanvändare via API
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    # Logga in användaren och hämta token
    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    # Skapa en review via API
    response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Coca Cola",
        "rating": 5,
        "review_text": "Väldigt uppfriskande!",
        "image_url": "https://example.com/cocacola.jpg"
    }, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 201
    data = response.get_json()
    assert data["message"] == "Review created successfully"
    assert data["review"]["drink_name"] == "Coca Cola"

# Testa att ta bort en review
def test_delete_review(client):
    # Skapa en testanvändare och en review via API
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    # Logga in och hämta token
    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    # Skapa review
    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Pepsi",
        "rating": 4,
        "review_text": "Helt okej."
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    # Ta bort review via API
    delete_response = client.delete("/review/delete", json={
        "user_id": user_id,
        "review_id": review_id
    }, headers={"Authorization": f"Bearer {token}"})

    assert delete_response.status_code == 200
    assert "deleted successfully" in delete_response.json["message"]

# Testa att gilla en review
def test_like_review(client):
    # Skapa en användare och en review via API
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    # Logga in och hämta token
    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    # Skapa review
    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Sprite",
        "rating": 3,
        "review_text": "Lite för söt."
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    # Gilla review via API
    like_response = client.post("/review/like", json={
        "user_id": user_id,
        "review_id": review_id
    }, headers={"Authorization": f"Bearer {token}"})

    assert like_response.status_code == 200
    assert f"Review {review_id} liked by {username}" in like_response.json["message"]

# Testa att ogilla en review
def test_unlike_review(client):
    # Skapa en användare och en review via API
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    # Logga in och hämta token
    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    # Skapa review
    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Fanta",
        "rating": 4,
        "review_text": "Ganska god."
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    # Gilla review via API
    like_response = client.post("/review/like", json={
        "user_id": user_id,
        "review_id": review_id
    }, headers={"Authorization": f"Bearer {token}"})
    assert like_response.status_code == 200

    # Ogilla review via API
    unlike_response = client.post("/review/unlike", json={
        "user_id": user_id,
        "review_id": review_id
    }, headers={"Authorization": f"Bearer {token}"})

    assert unlike_response.status_code == 200
    assert f"Review {review_id} unliked by {username}" in unlike_response.json["message"]

# Testa att lägga till en kommentar
def test_add_comment(client):
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Fanta",
        "rating": 4,
        "review_text": "Ganska god."
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    comment_response = client.post("/review/comment", json={
        "user_id": user_id,
        "review_id": review_id,
        "comment_text": "Håller med!"
    }, headers={"Authorization": f"Bearer {token}"})

    assert comment_response.status_code == 201
    assert "Comment added successfully" in comment_response.json["message"]

# Testa att ta bort en kommentar
def test_delete_comment(client):
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Pepsi",
        "rating": 3,
        "review_text": "Lite för söt."
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    comment_response = client.post("/review/comment", json={
        "user_id": user_id,
        "review_id": review_id,
        "comment_text": "Jag tycker detsamma!"
    }, headers={"Authorization": f"Bearer {token}"})

    assert comment_response.status_code == 201
    comment_id = comment_response.json["comment"]["id"]

    delete_response = client.delete("/review/comment/delete", json={
        "user_id": user_id,
        "comment_id": comment_id
    }, headers={"Authorization": f"Bearer {token}"})

    assert delete_response.status_code == 200
    assert f"Comment {comment_id} deleted successfully" in delete_response.json["message"]

def test_get_comments(client):
    username, password = generate_random_credentials()
    user_response = client.post("/user", json={"username": username, "password": password})
    assert user_response.status_code == 200
    user_id = user_response.json["user_id"]

    login_response = client.post("/user/login", json={"username": username, "password": password})
    token = login_response.get_json()["access_token"]

    review_response = client.post("/review/create", json={
        "user_id": user_id,
        "drink_name": "Coca Cola",
        "rating": 5,
        "review_text": "Bästa läsken!"
    }, headers={"Authorization": f"Bearer {token}"})

    assert review_response.status_code == 201
    review_id = review_response.json["review"]["id"]

    client.post("/review/comment", json={
        "user_id": user_id,
        "review_id": review_id,
        "comment_text": "Jag håller med!"
    }, headers={"Authorization": f"Bearer {token}"})

    # Skicka review_id som query-parameter istället för JSON
    comments_response = client.get(f"/review/comments?review_id={review_id}")
    
    assert comments_response.status_code == 200
    assert len(comments_response.json["comments"]) > 0
