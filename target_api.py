from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory "database"
users_db = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com"},
    3: {"id": 3, "name": "Charlie", "email": "charlie@example.com"},
}

admin_data = {
    "secret_key": "sk-super-secret-admin-key-12345",
    "database_url": "postgres://admin:password@prod-db:5432/main",
    "users_count": 3,
}


@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    uid = int(user_id)
    user = users_db.get(uid)
    if user:
        return jsonify(user), 200
    return jsonify({"error": "User not found"}), 404


@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    new_id = max(users_db.keys()) + 1
    users_db[new_id] = {
        "id": new_id,
        "name": data.get("name", ""),
        "email": data.get("email", ""),
    }
    return jsonify(users_db[new_id]), 201


@app.route("/search", methods=["POST"])
def search_users():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    query = data.get("query", "")
    dangerous_chars = ["'", ";", "--", "DROP", "OR 1=1", "UNION"]
    for char in dangerous_chars:
        if char.lower() in query.lower():
            raise Exception(f"Database error: syntax error near '{query}'")
    results = [
        u for u in users_db.values() if query.lower() in u["name"].lower()
    ]
    return jsonify({"results": results}), 200


@app.route("/admin", methods=["GET"])
def get_admin():
    return jsonify(admin_data), 200


if __name__ == "__main__":
    app.run(debug=False, port=5000)