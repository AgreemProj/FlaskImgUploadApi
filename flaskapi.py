from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, make_response
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter

ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

app = Flask(__name__)
limiter = Limiter(app)
app.config['SECRET_KEY'] = "uploadimage"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/dell/PycharmProjects/FlaskAPI/imagestorage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class ImageContents(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(300))
    data = db.Column(db.LargeBinary)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform the function!!!'})

	users = User.query.all()

	users_list = []

	for user in users:
		all_users = {}
		all_users['public_id'] = user.public_id
		all_users['name'] = user.name
		all_users['password'] = user.password
		all_users['admin'] = user.admin
		users_list.append(all_users)

	return jsonify({'users' : users_list})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_a_user(current_user ,public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform the function!!!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'Not a user!!'})

	user_data = {}
	user_data['public_id'] = user.public_id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin

	return jsonify({'message' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform the function!!!'})

	data = request.get_json()
	hashed_password = generate_password_hash(data['password'], method='adg123')
	new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
	db.session.add(new_user)
	db.session.commit()
	
	return jsonify({'message' : 'Successfully Created new user!!!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform the function!!!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'Not a user!!'})

	user.admin = True
	db.session.commit()

	return jsonify({'message' : 'User has been promoted!!'})

@app.route('/user/<public_id>', methods=['Delete'])
@token_required
def delete_user(current_user, public_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform the function!!!'})

	user = User.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'Not a user!!'})

	db.session.delete(user)
	db.session.commit()
	return jsonify({'message' : 'Successfully deleted the user!!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify!', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify!!', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
	return render_template("index.html")

@app.route('/upload', methods=['POST'])
@token_required
@limiter.limit("5 / minute", key_func = lambda : current_user)
def upload(current_user):
	file = request.files["formFileMultiple"]
	if file.filename == '':
		flash('No image has been selected!!')
		return redirect(url_for('home'))
	if file and allowed_file(file.filename):
		newfile = ImageContents(name=file.filename, data=file.read())
		db.session.add(newfile)
		db.session.commit()
		return file.filename
	else:
		flash('You can Only upload file with (png, jpg, jpeg, gif) extentions!!')
		return redirect(url_for('home'))

	return 'Thankyou!!'

if __name__ == "__main__":
	app.run(debug=True)