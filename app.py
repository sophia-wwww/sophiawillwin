from flask import Flask, request, jsonify, g
import bcrypt
import sqlite3
import os
import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- 数据库配置 ---
# 使用绝对路径，放在/tmp目录下以确保有写权限
DATABASE = os.path.join('/tmp', 'users.db')
logger.info(f"Database path: {DATABASE}")

# 创建表的SQL语句(内联替代schema.sql)
CREATE_TABLE_SQL = '''
                   CREATE TABLE IF NOT EXISTS users \
                   ( \
                       id \
                       INTEGER \
                       PRIMARY \
                       KEY \
                       AUTOINCREMENT, \
                       username \
                       TEXT \
                       UNIQUE \
                       NOT \
                       NULL, \
                       hashed_password \
                       TEXT \
                       NOT \
                       NULL
                   ); \
                   '''


# 函数：获取数据库连接
def get_db():
    try:
        db = getattr(g, '_database', None)
        if db is None:
            logger.debug("Creating new database connection")
            db = g._database = sqlite3.connect(DATABASE)
            # 设置 row_factory 以字典形式获取结果
            db.row_factory = sqlite3.Row
        return db
    except Exception as e:
        logger.error(f"Error getting database connection: {e}")
        raise


# 函数：在应用关闭时关闭数据库连接
@app.teardown_appcontext
def close_db(error):
    try:
        db = getattr(g, '_database', None)
        if db is not None:
            logger.debug("Closing database connection")
            db.close()
    except Exception as e:
        logger.error(f"Error closing database: {e}")


# 函数：初始化数据库，创建用户表
def init_db():
    try:
        logger.info("Initializing database...")
        with app.app_context():
            db = get_db()
            # 直接使用CREATE TABLE IF NOT EXISTS，无需检查表是否存在
            logger.debug("Creating users table if not exists")
            db.execute(CREATE_TABLE_SQL)
            db.commit()
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        # 不抛出异常，让应用继续启动


# 在应用启动时初始化数据库
with app.app_context():
    init_db()


# --- API 路由 (登录) ---
@app.route('/simple_authenticate', methods=['POST'])
def simple_authenticate():
    try:
        logger.debug("Authentication request received")
        auth_data = request.get_json()
        if not auth_data or 'username' not in auth_data or 'password' not in auth_data:
            logger.warning("Missing username or password in request")
            return jsonify({"status": "failed", "message": "Missing username or password"}), 400

        username = auth_data.get('username')
        password = auth_data.get('password')

        logger.debug(f"Authenticating user: {username}")

        db = get_db()
        # 从数据库获取哈希密码
        user = db.execute('SELECT hashed_password FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            stored_hashed_password = user['hashed_password']
            # 使用 bcrypt 检查密码
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                logger.info(f"Authentication successful for user: {username}")
                return jsonify({"status": "success", "message": "Authentication successful", "user_id": username}), 200
            else:
                logger.warning(f"Authentication failed for user: {username} (wrong password)")
                return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
        else:
            logger.warning(f"Authentication failed: user {username} not found")
            return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
    except Exception as e:
        logger.error(f"Error during authentication: {e}")
        return jsonify({"status": "error", "message": "Authentication failed due to server error"}), 500


# --- API 路由 (注册) ---
@app.route('/register', methods=['POST'])
def register():
    try:
        logger.debug("Registration request received")
        reg_data = request.get_json()

        if not reg_data or 'username' not in reg_data or 'password' not in reg_data:
            logger.warning("Missing username or password in registration request")
            return jsonify({"status": "failed", "message": "Missing username or password"}), 400

        username = reg_data.get('username')
        password = reg_data.get('password')

        logger.debug(f"Registering new user: {username}")

        db = get_db()
        # 检查用户名是否已存在
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

        if existing_user:
            logger.warning(f"Registration failed: username {username} already taken")
            return jsonify({"status": "failed", "message": "Username already exists"}), 409

        # 对密码进行哈希
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            # 将新用户数据插入数据库
            db.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)',
                       (username, hashed_password.decode('utf-8')))
            db.commit()

            logger.info(f"User {username} registered successfully")
            return jsonify({"status": "success", "message": "Registration successful"}), 200

        except Exception as e:
            db.rollback()
            logger.error(f"Error during database operation for user {username}: {e}")
            return jsonify({"status": "error", "message": "Registration failed due to server error"}), 500
    except Exception as e:
        logger.error(f"Error during registration: {e}")
        return jsonify({"status": "error", "message": "Registration failed due to server error"}), 500


# 添加健康检查端点
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Server is running"}), 200


# --- 应用启动 ---
if __name__ == '__main__':
    # 运行 Flask 应用
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
else:
    # 在生产环境下也初始化数据库
    with app.app_context():
        init_db()