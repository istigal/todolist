import uuid
from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    email = db.Column(db.String(250), unique=True, nullable=False, )
    password = db.Column(db.String(250), nullable=False)
    username = db.Column(db.String(100), nullable=False, unique=True)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.String(50))
    completed = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        bearer = request.headers.get('Authorization').split()[1]
        if not bearer:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(bearer, app.config['SECRET_KEY'], algorithms=["HS256"], options={"verify_exp": False})
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return wrapper


@app.route('/')
def home():
    return jsonify({'message': 'Welcome!'})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    new_user = User(public_id=str(uuid.uuid4()),
                    username=data['username'],
                    email=data['email'],
                    password=generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=16),
                    admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user created'})


@app.route('/users')
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    users = User.query.all()
    all_users = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['name'] = user.username
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        all_users.append(user_data)
    return all_users


@app.route('/user/<user_id>')
@token_required
def get_user_by_id(current_user, user_id):
    if current_user.public_id != user_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=user_id).first()
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['email'] = user.email
    user_data['name'] = user.username
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify(user_data)


@app.route('/user/<user_id>', methods=['PUT'])
@token_required
def promote_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user was promoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user has been deleted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if not check_password_hash(user.password, auth.get('password')):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    token = jwt.encode(
        {'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
        app.config['SECRET_KEY'])
    return jsonify({'token': token})


@app.route('/todos')
@token_required
def all_todos(current_user):
    todos = Todo.query.filter_by(user_id=current_user.public_id).all()
    output = []
    for todo in todos:
        todo_list = {
            'id': todo.id,
            'text': todo.text,
            'completed': todo.completed
        }
        output.append(todo_list)
    return jsonify({'todos': output})


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    todo = Todo(text=data['text'], user_id=current_user.public_id, completed=False)
    db.session.add(todo)
    db.session.commit()
    return jsonify({'message': 'Todo created!'})


@app.route('/todo/<todo_id>')
@token_required
def get_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.public_id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'Todo not found'})
    output = {
        'id': todo.id,
        'completed': todo.completed,
        'text': todo.text
    }
    return jsonify(output)


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.public_id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'Todo not found'})
    todo.completed = True
    db.session.commit()
    return jsonify({'message': 'Todo completed.'})


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.public_id, id=todo_id).first()
    if not todo:
        return jsonify({'message': 'Todo not found'})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({'message': 'Todo deleted.'})

if __name__ == '__main__':
    app.run(debug=True)
