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
DATABASE = os.path.join('/tmp', 'users.db') # Render等平台通常/tmp可写
logger.info(f"Database path: {DATABASE}")

# 更新表的SQL语句，添加用户资料字段
CREATE_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL,
    height REAL,          -- 使用 REAL (兼容 FLOAT)
    weight REAL,          -- 使用 REAL (兼容 FLOAT)
    age INTEGER,
    gender TEXT
);
'''

# 函数：获取数据库连接
def get_db():
    try:
        db = getattr(g, '_database', None)
        if db is None:
            logger.debug("Creating new database connection")
            db = g._database = sqlite3.connect(DATABASE)
            db.row_factory = sqlite3.Row # 以字典形式获取结果
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
            logger.debug("Executing CREATE TABLE IF NOT EXISTS")
            db.execute(CREATE_TABLE_SQL)
            db.commit()
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

# 在应用启动时初始化数据库
try:
    with app.app_context():
        init_db()
except Exception as e:
    logger.error(f"Failed to initialize DB during app setup: {e}")

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
        user = db.execute(
            'SELECT id, username, hashed_password, height, weight, age, gender FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        if user:
            stored_hashed_password = user['hashed_password']
            if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
                logger.info(f"Authentication successful for user: {username}")
                user_profile = {
                    "username": user['username'],
                    "height": user['height'],
                    "weight": user['weight'],
                    "age": user['age'],
                    "gender": user['gender']
                }
                return jsonify({
                    "status": "success",
                    "message": "Authentication successful",
                    "user_id": username, # Keep user_id for consistency with previous versions if needed
                    "user_profile": user_profile
                }), 200
            else:
                logger.warning(f"Authentication failed for user: {username} (wrong password)")
                return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
        else:
            logger.warning(f"Authentication failed: user {username} not found")
            return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
    except sqlite3.Error as db_err:
        logger.error(f"Database error during authentication for {username}: {db_err}")
        return jsonify({"status": "error", "message": "Authentication failed due to database error"}), 500
    except Exception as e:
        logger.error(f"Unexpected error during authentication: {e}")
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
        height = reg_data.get('height') # Optional fields
        weight = reg_data.get('weight')
        age = reg_data.get('age')
        gender = reg_data.get('gender')
        logger.debug(f"Registering new user: {username}")

        db = get_db()
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing_user:
            logger.warning(f"Registration failed: username {username} already taken")
            return jsonify({"status": "failed", "message": "Username already exists"}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Basic validation before insert (optional but recommended)
        validated_data = {
            'username': username,
            'hashed_password': hashed_password.decode('utf-8'),
            'height': None, 'weight': None, 'age': None, 'gender': None
        }
        try:
            if height is not None: validated_data['height'] = float(height)
            if weight is not None: validated_data['weight'] = float(weight)
            if age is not None: validated_data['age'] = int(age)
            if gender is not None: validated_data['gender'] = str(gender)
        except ValueError as ve:
             logger.warning(f"Invalid data type during registration for {username}: {ve}")
             return jsonify({"status": "failed", "message": f"Invalid data type provided: {ve}"}), 400

        db.execute(
            'INSERT INTO users (username, hashed_password, height, weight, age, gender) VALUES (?, ?, ?, ?, ?, ?)',
            (validated_data['username'], validated_data['hashed_password'], validated_data['height'],
             validated_data['weight'], validated_data['age'], validated_data['gender'])
        )
        db.commit()
        logger.info(f"User {username} registered successfully")
        return jsonify({"status": "success", "message": "Registration successful"}), 201 # Use 201 Created

    except sqlite3.IntegrityError:
         db.rollback()
         logger.warning(f"Registration failed: username {username} already taken (IntegrityError)")
         return jsonify({"status": "failed", "message": "Username already exists"}), 409
    except sqlite3.Error as db_err:
        db.rollback()
        logger.error(f"Database error during registration for {username}: {db_err}")
        return jsonify({"status": "error", "message": "Registration failed due to database error"}), 500
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error during registration: {e}")
        return jsonify({"status": "error", "message": "Registration failed due to server error"}), 500

# --- API路由 (获取用户资料) ---
@app.route('/user_profile/<username>', methods=['GET'])
def get_user_profile(username):
    # SECURITY NOTE: In a real app, verify the requesting user is allowed to see this profile!
    try:
        logger.debug(f"Getting profile for user: {username}")
        db = get_db()
        user = db.execute(
            'SELECT username, height, weight, age, gender FROM users WHERE username = ?',
            (username,)
        ).fetchone()

        if not user:
            logger.warning(f"User profile not found: {username}")
            return jsonify({"status": "failed", "message": "User not found"}), 404

        user_dict = dict(user) # Convert SQLite Row to dict
        logger.info(f"User profile retrieved for: {username}")
        return jsonify({"status": "success", "user_profile": user_dict}), 200

    except sqlite3.Error as db_err:
         logger.error(f"Database error retrieving profile for {username}: {db_err}")
         return jsonify({"status": "error", "message": "Failed to retrieve user profile due to database error"}), 500
    except Exception as e:
        logger.error(f"Error retrieving user profile for {username}: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve user profile due to server error"}), 500

# --- API路由 (更新用户资料 - 支持部分更新) ---
@app.route('/user_profile/<username>', methods=['PUT'])
def update_user_profile(username):
    # SECURITY NOTE: In a real app, verify the requesting user IS <username> or has permission!
    try:
        logger.debug(f"Attempting partial profile update for user: {username}")
        profile_data = request.get_json()

        if not profile_data:
            logger.warning(f"Missing profile data in PUT request for {username}")
            return jsonify({"status": "failed", "message": "Missing profile data"}), 400

        db = get_db()
        # 检查用户是否存在
        existing_user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if not existing_user:
            logger.warning(f"Update failed: user {username} not found")
            return jsonify({"status": "failed", "message": "User not found"}), 404

        # --- Start: Partial Update Logic ---
        fields_to_update = {}
        valid_fields = ['height', 'weight', 'age', 'gender']

        for field in valid_fields:
            if field in profile_data: # Check if key exists in request JSON
                value = profile_data[field]
                # Basic data type validation for fields being updated
                try:
                    if field == 'height' and value is not None:
                        fields_to_update[field] = float(value)
                    elif field == 'weight' and value is not None:
                        fields_to_update[field] = float(value)
                    elif field == 'age' and value is not None:
                        fields_to_update[field] = int(value)
                    elif field == 'gender': # Allow string or null
                         fields_to_update[field] = str(value) if value is not None else None
                    elif value is None: # Allow explicit null setting for other fields
                         fields_to_update[field] = None
                except ValueError:
                    logger.warning(f"Invalid data type for field '{field}' for user {username}")
                    return jsonify({"status": "failed", "message": f"Invalid data type for field '{field}'"}), 400

        if not fields_to_update:
            logger.info(f"No valid fields provided to update for user: {username}")
            # Decide what to return: success with message, or maybe 400? Let's return success.
            return jsonify({"status": "success", "message": "No fields provided or updated"}), 200

        # Dynamically build the SET clause and values list
        set_clause = ", ".join([f"{key} = ?" for key in fields_to_update.keys()])
        values = list(fields_to_update.values())
        values.append(username) # Add username for the WHERE clause

        sql = f'UPDATE users SET {set_clause} WHERE username = ?'
        logger.debug(f"Executing SQL: {sql} with values: {values}")
        # --- End: Partial Update Logic ---

        db.execute(sql, values)
        db.commit()

        logger.info(f"User profile partially updated for: {username}")
        return jsonify({"status": "success", "message": "Profile updated successfully"}), 200

    except sqlite3.Error as db_err:
        db.rollback()
        logger.error(f"Database error during profile update for {username}: {db_err}")
        return jsonify({"status": "error", "message": "Profile update failed due to database error"}), 500
    except Exception as e:
        db.rollback() # Ensure rollback on any exception during the process
        logger.error(f"Error updating user profile for {username}: {e}")
        return jsonify({"status": "error", "message": "Profile update failed due to server error"}), 500


# 添加健康检查端点
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "Server is running"}), 200


# --- 应用启动 ---
if __name__ == '__main__':
    # Development server
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
# else: Production environment handled by WSGI server