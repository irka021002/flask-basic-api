import os
import bcrypt
import datetime
import jwt
from flask import Flask, request, jsonify, make_response, g
from database import db
from flask_migrate import Migrate
from dotenv import load_dotenv
from functools import wraps
from libs.ValidateFields import validate_fields
from models.user import User
from models.role import Role

load_dotenv()
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
db.init_app(app)
migrate = Migrate(app, db)

def authenticate(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('auth')
        if not token:
            return jsonify({
                'status': 401, 
                'error': True, 
                'message': f'Login terlebih dahulu'
            }), 400
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({
                'status': 401, 
                'error': True, 
                'message': f'Login terlebih dahulu'
            }), 400
        except jwt.InvalidTokenError:
            return jsonify({
                'status': 401, 
                'error': True, 
                'message': f'Login terlebih dahulu'
            }), 400
        
        return func(*args, **kwargs)
    return decorated

@app.route("/api/login", methods=["POST"])
def login():
    data = request.form
    fields = ["password"]
    valid, missing_fields = validate_fields(data,fields)
    
    if not valid:
        return jsonify({
            'status': 400, 
            'error': True, 
            'message': f'{", ".join(missing_fields)} tidak boleh kosong'
        }), 400
    
    password = data["password"]
    
    if 'username' in data:
        username = data["username"]
        user = User.query.filter_by(username = username).first()
        
        if bcrypt.checkpw(password.encode(), user.password.encode()):
            token = jwt.encode({
                'id': user.id,
                'nama': user.nama,
                'username': user.username,
                'email': user.email,
                'role_id': user.role_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            response = make_response(jsonify({
                'status': 200, 
                'error': False, 
                'message': f'berhasil login'
            }))
            response.set_cookie('auth', token, max_age=86400)
            return response
        else:
            return jsonify({
                'status': 400, 
                'error': True, 
                'message': f'password salah'
            }), 400
    
    if 'email' in data:
        email = data["email"]
        user = User.query.filter_by(email = email).first()
        
        if bcrypt.checkpw(password.encode(), user.password):
            token = jwt.encode({
                'id': user.id,
                'nama': user.nama,
                'username': user.username,
                'email': user.email,
                'role_id': user.role_id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            response = make_response(jsonify({
                'status': 200, 
                'error': False, 
                'message': f'berhasil login'
            }))
            response.set_cookie('auth', token, max_age=86400)
            return response
        else:
            return jsonify({
                'status': 400, 
                'error': True, 
                'message': f'password salah'
            }), 400
    
    return jsonify({
        'status': 400, 
        'error': True, 
        'message': f'username/email tidak boleh kosong'
    }), 400

@app.route("/api/logout", methods=["GET"])
def logout():
    response = make_response(jsonify({
                    'status': 200, 
                    'error': False, 
                    'message': f'berhasil logout'
                }))
    
    response.set_cookie('auth', '', max_age=-1)
    return response

@app.route("/api/user", methods=["POST"])
@authenticate
def createUser():
    data = request.form
    fields = ["username", "nama", "email", "password", "role_id"]
    valid, missing_fields = validate_fields(data,fields)
    
    if not valid:
        return jsonify({
            'status': 400, 
            'error': True, 
            'message': f'{", ".join(missing_fields)} tidak boleh kosong'
        }), 400
    
    username = data["username"]
    email = data["email"]
    nama = data["nama"]
    role_id = data["role_id"]
    password = data["password"].encode()
    
    checkUsername = User.query.filter_by(username = username).first()
    if checkUsername is not None:
        return jsonify({
            'status': 409, 
            'error': True, 
            'message': 'username telah digunakan'
        }), 409
    
    checkEmail = User.query.filter_by(email = email).first()
    if checkEmail is not None:
        return jsonify({
            'status': 409, 
            'error': True, 
            'message': 'email telah digunakan'
        }), 409
    
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode()
    
    user = User(username=username, nama=nama, email=email, password=hashed_password, role_id = role_id)
    
    db.session.add(user)
    db.session.commit()
    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil terdaftar dengan id: {user.id}', 
        'data': {
            'user': {
                'id': user.id, 
                'username': user.username, 
                'email': user.email,
                'nama': user.nama,
                'role_id': user.role_id
            }
        }
    }), 200

@app.route("/api/user", methods=["GET"])
def users():
    users = User.query.all()
    
    serialized = [{
            'id': item.id,
            'username': item.username,
            'email': item.email,
            'nama': item.nama,
            'role_id': item.role_id
        } for item in users]

    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil mendapatkan data user', 
        'data': serialized
    }), 200

@app.route("/api/user/<int:id>", methods=["GET"])
def user(id):
    user = User.query.get(id)
    
    if not user:
        return jsonify({
            'status': 404, 
            'error': True, 
            'message': 'user tidak ditemukan'
        }), 404

    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil mendapatkan data user', 
        'data': {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'nama': user.nama,
                'role_id': user.role_id
            }
        }
    }), 200
    
@app.route("/api/user/<int:id>", methods=["PUT"])
@authenticate
def updateUser(id):
    try:
        data = request.form
        user = User.query.get(id)
        
        if not user:
            return jsonify({
                'status': 404, 
                'error': True, 
                'message': 'user tidak ditemukan'
            }), 404
            
        fields = ["username", "email", "nama", "role_id"]
        valid, missing_fields = validate_fields(data,fields)
        
        if not valid:
            return jsonify({
                'status': 400, 
                'error': True, 
                'message': f'{", ".join(missing_fields)} tidak boleh kosong'
            }), 400
        
        username = data["username"]
        email = data["email"]
        nama = data["nama"]
        role_id = data["role_id"]
        
        checkUsername = User.query.filter_by(username = username).first()
        if (checkUsername is not None) and (username != user.username):
            return jsonify({
                'status': 409, 
                'error': True, 
                'message': 'username telah digunakan'
            }), 409
        
        checkEmail = User.query.filter_by(email = email).first()
        if (checkEmail is not None) and (email != user.email):
            return jsonify({
                'status': 409, 
                'error': True, 
                'message': 'email telah digunakan'
            }), 409
        
        user.username = username
        user.email = email
        user.nama = nama
        user.role_id = role_id
        
        if 'password' in data:
            password = data['password'].encode()
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode()
            user.password = hashed_password
        
        db.session.commit()
            
        return jsonify({
            'status': 200,
            'error': False,
            'message': "user berhasil diubah"
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 500,
            'error': True,
            'message': str(e)
        })

@app.route("/api/user/<int:id>", methods=["DELETE"])
@authenticate
def deleteUser(id):
    try:
        user = User.query.get(id)
        
        if not user:
            return jsonify({
                'status': 404, 
                'error': True, 
                'message': 'user tidak ditemukan'
            }), 404
        
        db.session.delete(user)
        db.session.commit()
            
        return jsonify({
            'status': 200,
            'error': False,
            'message': "user berhasil dihapus"
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 500,
            'error': True,
            'message': str(e)
        })

@app.route("/api/role", methods=["POST"])
@authenticate
def createRole():
    data = request.form
    fields = ["nama"]
    valid, missing_fields = validate_fields(data,fields)
    
    if not valid:
        return jsonify({
            'status': 400, 
            'error': True, 
            'message': f'{", ".join(missing_fields)} tidak boleh kosong'
        }), 400
    
    nama = data["nama"]
    
    checkNama = Role.query.filter_by(nama = nama).first()
    if checkNama is not None:
        return jsonify({
            'status': 409, 
            'error': True, 
            'message': 'nama role telah digunakan'
        }), 409
    
    role = Role(nama=nama)
    
    db.session.add(role)
    db.session.commit()
    
    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil membuat dengan id: {role.id}', 
        'data': {
            'role': {
                'id': role.id, 
                'nama': role.nama
            }
        }
    }), 200

@app.route("/api/role", methods=["GET"])
def roles():
    roles = Role.query.all()
    
    serialized = [{
            'id': item.id,
            'nama': item.nama
        } for item in roles]

    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil mendapatkan data role', 
        'data': serialized
    }), 200

@app.route("/api/role/<int:id>", methods=["GET"])
def role(id):
    role = Role.query.get(id)
    
    if not role:
        return jsonify({
            'status': 404, 
            'error': True, 
            'message': 'role tidak ditemukan'
        }), 404

    return jsonify({
        'status': 200, 
        'error': False, 
        'message': f'Berhasil mendapatkan data role', 
        'data': {
            'role': {
                'id': role.id,
                'nama': role.nama
            }
        }
    }), 200

@app.route("/api/role/<int:id>", methods=["PUT"])
@authenticate
def updateRole(id):
    try:
        data = request.form
        role = Role.query.get(id)
        
        if not role:
            return jsonify({
                'status': 404, 
                'error': True, 
                'message': 'role tidak ditemukan'
            }), 404
            
        fields = ["nama"]
        valid, missing_fields = validate_fields(data,fields)
        
        if not valid:
            return jsonify({
                'status': 400, 
                'error': True, 
                'message': f'{", ".join(missing_fields)} tidak boleh kosong'
            }), 400
        
        nama = data["nama"]
        
        checkNama = Role.query.filter_by(nama = nama).first()
        if checkNama is not None:
            return jsonify({
                'status': 409, 
                'error': True, 
                'message': 'nama telah digunakan'
            }), 409
        
        role.nama = nama
        
        db.session.commit()
            
        return jsonify({
            'status': 200,
            'error': False,
            'message': "role berhasil diubah"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 500,
            'error': True,
            'message': str(e)
        }), 500

@app.route("/api/role/<int:id>", methods=["DELETE"])
@authenticate
def deleteRole(id):
    try:
        role = Role.query.get(id)
        
        if not role:
            return jsonify({
                'status': 404, 
                'error': True, 
                'message': 'role tidak ditemukan'
            }), 404
        
        db.session.delete(role)
        db.session.commit()
            
        return jsonify({
            'status': 200,
            'error': False,
            'message': "role berhasil dihapus"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 500,
            'error': True,
            'message': str(e)
        }), 500
        

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=os.getenv("DEBUG"))