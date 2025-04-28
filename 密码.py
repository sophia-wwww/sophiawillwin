from flask import Flask, request, jsonify

app = Flask(__name__)

# --- 硬编码的用户名和密码 (极度不安全，仅用于演示) ---
# 在生产环境中，密码绝不能明文存储在这里！！！
SIMPLE_USERS = {
    "testuser": "testpass123",
    "admin": "admin123",
}
# --- 硬编码用户数据结束 ---

@app.route('/simple_authenticate', methods=['POST'])
def simple_authenticate():
    """
    接收用户名和密码，进行简单的硬编码比对。
    """
    # 1. 获取请求中的 JSON 数据
    auth_data = request.get_json()

    # 2. 检查是否包含 username 和 password 字段
    if not auth_data or 'username' not in auth_data or 'password' not in auth_data:
        return jsonify({"status": "failed", "message": "Missing username or password"}), 400

    username = auth_data.get('username')
    password = auth_data.get('password')

    print(f"Received login attempt for username: {username}") # 用于调试

    # 3. 进行硬编码比对
    # 直接比较接收到的明文密码和硬编码的明文密码
    if username in SIMPLE_USERS and SIMPLE_USERS[username] == password:
        # 用户存在且密码匹配，验证成功
        print(f"Authentication successful for user: {username}")
        return jsonify({"status": "success", "message": "Authentication successful", "user_id": username}), 200
    else:
        # 用户不存在或密码不匹配，验证失败
        print(f"Authentication failed for user: {username} (invalid credentials)")
        return jsonify({"status": "failed", "message": "Invalid username or password"}), 401

# 运行 Flask 应用 (在开发环境中)
if __name__ == '__main__':
    # 这是一个简单的开发服务器，不适合生产环境
    app.run(debug=True, port=5000) # 默认运行在 http://127.0.0.1:5000/
