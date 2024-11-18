from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from passlib.context import CryptContext
from flask_caching import Cache
import time
import requests
from datetime import datetime
from math import ceil


# Flask 应用配置
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./jimicms.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = "gongzhengkejimimedia"  # 更改为你的密钥
app.config["CACHE_TYPE"] = "SimpleCache"  # 配置缓存类型
app.config["CACHE_DEFAULT_TIMEOUT"] = 7200  # 缓存过期时间设置为7200秒

db = SQLAlchemy(app)
jwt = JWTManager(app)
cache = Cache(app)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# 数据库模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    hashed_password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)


class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.utcnow)
    update_time = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    status = db.Column(db.String(255), default="published")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = db.relationship("User", backref=db.backref("contents", lazy=True))


# 创建数据库表
with app.app_context():
    db.create_all()


# 密码哈希函数
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def Result(code=500, message="error", data=[]):

    json_dict = {"code": code, "message": message, "data": data}
    return jsonify(json_dict)

# 首页
@app.route("/", methods=["GET"])
def index():
    return "Hello world."

# 用户登录
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.hashed_password):
        return Result(500, "用户名或密码错误")
    userInfo = {
        "username": user.username,
        "name": user.name,
        "phone": user.phone,
        "gender": user.gender,
        "is_admin": user.is_admin,
    }
    access_token = create_access_token(
        identity=username, expires_delta=timedelta(minutes=10080)
    )
    return Result(200, "登录成功", {"token": access_token, "userInfo": userInfo})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    phone = data.get('phone')
    gender = data.get('gender')
    is_admin = False

    if User.query.filter_by(username=username).first():
        return jsonify({"code": 1, "message": "用户已存在", "data": None }), 400

    hashed_password = get_password_hash(password)
    new_user = User(username=username, hashed_password=hashed_password, name=name, phone=phone, gender=gender, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"code": 0, "message": "注册成功", "data": {"username": username} })

# 获取当前用户信息
@app.route("/api/userinfo", methods=["GET"])
@jwt_required()
def get_current_user():
    current_user_username = get_jwt_identity()
    user = User.query.filter_by(username=current_user_username).first()
    return jsonify(
        {
            "code": 200,
            "message": "获取成功",
            "data": {
                "username": user.username,
                "name": user.name,
                "phone": user.phone,
                "gender": user.gender,
                "is_admin": user.is_admin,
            },
        }
    )


# 获取文章列表
@app.route("/api/content", methods=["GET"])
def get_content_list():
    # 获取参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # 获取总数
    total_contents = Content.query.count()
    
    # 计算页数
    contents = Content.query.offset((page - 1) * per_page).limit(per_page).all()
    
    # 计算总数
    total_pages = ceil(total_contents / per_page)
    
    # Return
    return Result(
        200,
        "获取成功",
        {
            "current_page": page,
            "total_pages": total_pages,
            "total_items": total_contents,
            "items_per_page": per_page,
            "content_list": [
                {
                    "id": content.id,
                    "title": content.title,
                    "content": content.content,
                    "create_time": content.create_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "update_time": content.update_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": content.status,
                }
                for content in contents
            ]
        }
    )

# 获取文章详情
@app.route("/api/content/<int:content_id>", methods=["GET"])
def get_content_detail(content_id):
    content = Content.query.get(content_id)
    if not content:
        return Result(500, "参数错误")
    
    return Result(
            200,
            "获取成功",
            {
                "id": content.id,
                "title": content.title,
                "content": content.content,
                "create_time": content.create_time.strftime("%Y-%m-%d %H:%M:%S"),
                "update_time": content.update_time.strftime()
            }
    )

# 管理员添加文章
@app.route("/api/content/add", methods=["POST"])
@jwt_required()
def add_content():
    data = request.get_json()
    return Result(200,"添加成功",data)

def get_content_list_by_keyword(keyword):
    return cache.get(keyword)

def set_content_list_by_keyword(keyword, content_list):
    cache.set(keyword, content_list, timeout=7200)
    
    return content_list

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)