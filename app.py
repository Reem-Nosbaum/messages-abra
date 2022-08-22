import datetime
import uuid
from flask import Flask, request, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'not protected'  # creating a session
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://oluoxsrfnhpcjt:5a602a2716aa4f8818d7a8661160c045f2c8b75530325bfbd7530a31c204b742@ec2-54-86-106-48.compute-1.amazonaws.com:5432/dfpe2vq4pqscri"  # sql database

# sqlite database, for local check
# app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///abra.sqlite"


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String, unique=True, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)


class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String, nullable=False)
    message = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean(), nullable=False)
    send_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)

    def get_dict(self):
        return {'id': self.id,
                'sender': self.sender,
                'receiver': self.receiver,
                'subject': self.subject,
                'message': self.message,
                'read': self.read,
                'send_date': self.send_date}


@app.route("/signup", methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    if Users.query.filter_by(username=username).all():  # checking if username already exists in the db
        return make_response(jsonify({'task': 'signup', 'status': 'failed', 'reason': 'username already exists'}), 409)
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), username=username, password=hashed_password)
    db.session.add(new_user)  # adding the new user to the db
    db.session.commit()
    return make_response(jsonify({'task': 'signup', 'status': 'success'}), 200)


@app.route('/login', methods=['POST'])
def login():
    password: str = request.form['password']
    username: str = request.form['username']
    # checking if the user and password are in the db
    user: list[Users] = Users.query.filter_by(username=username).all()
    if user and check_password_hash(user[0].password, password):
        session['user_id'] = user[0].id
        return make_response(jsonify({'task': 'login', 'status': 'success'}), 200)
    return make_response(jsonify({'task': 'login', 'status': 'failed'}), 401)


@app.route("/logout", methods=['POST'])
def logout():
    if 'user_id' in session:
        session.pop('user_id')
        return make_response(jsonify({'task': 'logout', 'status': 'success'}), 200)
    return make_response(jsonify({'task': 'logout', 'status': 'failed'}), 401)


@app.route('/messages', methods=['GET', 'POST'])
def get_all_messages():
    if 'user_id' not in session:
        return make_response(jsonify(
            {'task': 'get or post message', 'status': 'failed', 'reason': 'user not authenticated'}), 401)

    if request.method == 'GET':
        if 'unread' in request.args:
            all_messages = Messages.query.filter_by(read=False, sender=session['user_id']).all()
        else:
            all_messages = Messages.query.filter_by(sender=session['user_id']).all()
        all_dict_messages = [message.get_dict() for message in all_messages]
        for message in all_messages:
            message.read = True
        db.session.commit()
        return make_response(jsonify(all_dict_messages), 200)
    elif request.method == 'POST':
        if 'receiver' and 'subject' and 'message' in request.form:
            receiver = request.form['receiver']
            receiver: list[Messages] = Messages.query.filter_by(receiver=receiver).all()  #check if receiver id in exists
            subject = request.form['subject']
            message = request.form['message']
            new_message = Messages(sender=session['user_id'], receiver=receiver, subject=subject, message=message, read=False)
            db.session.add(new_message)  # adding the new message to the db
            db.session.commit()
            return make_response(jsonify({'task': 'message', 'status': 'success'}), 200)
        return make_response(jsonify({'task': 'message', 'status': 'failed'}), 401)


@app.route('/messages/<int:id_>', methods=['GET', 'DELETE'])
def message_by_id(id_):
    if 'user_id' not in session:
        return make_response(jsonify({'task': 'get or post message', 'status': 'failed', 'reason': 'user not authenticated'}), 401)

    get_message_by_id: list[Messages] = Messages.query.filter_by(id=id_).all()  # getting the message by id
    if request.method == 'GET':
        all_dict_messages: list[dict] = [message.get_dict() for message in get_message_by_id]
        return make_response(jsonify(all_dict_messages), 200)

    elif request.method == 'DELETE':
        if get_message_by_id:
            Messages.query.filter_by(id=id_).delete()
            db.session.commit()
            return make_response(jsonify({'task': 'delete a message', 'status': 'success'}), 200)
        return make_response(jsonify({'task': 'delete a message', 'status': 'failed',
                                      'reason': 'message not exists'}), 200)

if __name__ == '__main__':
    app.run(debug=True)
