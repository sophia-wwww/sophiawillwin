from flask import Flask, request, jsonify, g  # 添加了g的导入
import bcrypt
import sqlite3 # 导入 sqlite3

app = Flask(__name__)

# --- 数据库配置 ---
DATABASE = 'users.db' # SQLite 数据库文件名

# 函数：获取数据库连接
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # 设置 row_factory 以字典形式获取结果
        db.row_factory = sqlite3.Row
    return db

# 函数：在应用关闭时关闭数据库连接
@app.teardown_appcontext
def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 函数：初始化数据库，创建用户表
def init_db():
    with app.app_context():
        db = get_db()
        # 使用 exists 判断表是否已存在，避免重复创建报错
        cursor = db.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone() is None:
            with app.open_resource('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()

# --- API 路由 (登录) ---
# 保留之前的登录路由 /simple_authenticate
@app.route('/simple_authenticate', methods=['POST'])
def simple_authenticate():
    auth_data = request.get_json()
    if not auth_data or 'username' not in auth_data or 'password' not in auth_data:
        return jsonify({"status": "failed", "message": "Missing username or password"}), 400

    username = auth_data.get('username')
    password = auth_data.get('password') # 接收到的密码是明文

    db = get_db()
    # 从数据库获取哈希密码
    user = db.execute('SELECT hashed_password FROM users WHERE username = ?', (username,)).fetchone()

    if user:
        stored_hashed_password = user['hashed_password']
        # 使用 bcrypt 检查密码
        # 注意：checkpw 需要 bytes 类型的明文密码和哈希密码
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            print(f"Authentication successful for user: {username}")
            return jsonify({"status": "success", "message": "Authentication successful", "user_id": username}), 200
        else:
            print(f"Authentication failed for user: {username} (wrong password)")
            return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
    else:
        print(f"Authentication failed: user {username} not found")
        return jsonify({"status": "failed", "message": "Invalid username or password"}), 401


# --- API 路由 (注册) ---
@app.route('/register', methods=['POST'])
def register():
    reg_data = request.get_json()

    if not reg_data or 'username' not in reg_data or 'password' not in reg_data:
        return jsonify({"status": "failed", "message": "Missing username or password"}), 400

    username = reg_data.get('username')
    password = reg_data.get('password') # 接收到的密码是明文

    db = get_db()
    # 检查用户名是否已存在
    existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

    if existing_user:
        print(f"Registration failed: username {username} already taken")
        # 通常返回 409 Conflict 表示资源冲突
        return jsonify({"status": "failed", "message": "Username already exists"}), 409 # HTTP 409 Conflict

    # 对密码进行哈希
    # gensalt() 生成一个随机盐值，hashpw() 使用盐值和密码生成哈希
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        # 将新用户数据插入数据库
        db.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)',
                   (username, hashed_password.decode('utf-8'))) # 存储为 utf-8 字符串
        db.commit() # 提交事务，保存更改

        print(f"User {username} registered successfully")
        return jsonify({"status": "success", "message": "Registration successful"}), 200

    except Exception as e:
        # 捕获数据库操作中的错误
        db.rollback() # 回滚事务，撤销插入操作
        print(f"Error during registration for user {username}: {e}")
        return jsonify({"status": "error", "message": "Registration failed due to server error"}), 500 # HTTP 500 Internal Server Error


# --- 应用启动 ---
if __name__ == '__main__':
    # 首次运行时初始化数据库
    init_db()
    # 运行 Flask 应用
    app.run(debug=True, port=5000)