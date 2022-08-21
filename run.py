import datetime
import uuid
from flask import Flask, request, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = 'not protected'  # creating a session
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///abra.sqlite"  # sql database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


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
        return make_response(jsonify({'task': 'signup', 'status': 'failed', 'reason': 'username already exists'}))  # add the right status code
    hashed_password = generate_password_hash(password, method='sha256')
    new_user = Users(public_id=str(uuid.uuid4()), username=username, password=hashed_password)
    db.session.add(new_user)  # adding the new user to the db
    db.session.commit()
    session['user'] = username
    return make_response(jsonify({'task': 'signup', 'status': 'success'}), 200)


@app.route('/login', methods=['POST'])
def login():
    password: str = request.form['password']
    username: str = request.form['username']
    user: list[Users] = Users.query.filter_by(username=username).all()
    # checking if the user and password are in the db
    if user and check_password_hash(user[0].password, password):
        session['user'] = username
        session['user_id'] = user[0].id
        return make_response(jsonify({'task': 'login', 'status': 'success'}), 200)
    return make_response(jsonify({'task': 'login', 'status': 'failed'}), 401)


@app.route("/logout", methods=['DELETE'])
def logout():
    if 'user' in session:
        session.pop('user')  # removing the username from the session
        return make_response(jsonify({'task': 'logout', 'status': 'success'}), 200)
    return make_response(jsonify({'task': 'logout', 'status': 'failed'}), 401)


@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if 'user' in session:
        all_messages = Messages.query.filter_by(read=False).all()
        all_dict_messages = [message.get_dict() for message in all_messages]
        if request.method == 'GET':
            read_message = Messages(read=True)
            print(read_message)
            return make_response(jsonify(all_dict_messages), 200)
        elif request.method == 'POST':
            receiver = request.form['receiver']
            subject = request.form['subject']
            message = request.form['message']
            new_message = Messages(sender=session['user_id'], receiver=receiver, subject=subject, message=message, read=False)
            db.session.add(new_message)  # adding the new message to the db
            db.session.commit()
            return make_response(jsonify({'task': 'message', 'status': 'success'}))  # add status
    return make_response(jsonify({'task': 'get or post message', 'status': 'failed', 'reason': 'user not authenticated'}))  # add status


@app.route('/messages/<int:id_>', methods=['GET', 'DELETE'])
def message_by_id(id_):
    all_messages = Messages.query.filter_by(sender=id_).all()
    all_dict_messages = [message.get_dict() for message in all_messages]
    if 'user' in session:
        if request.method == 'GET':
            return all_dict_messages
        elif request.method == 'DELETE':
            Messages.query.filter_by(id=id_).delete()
            db.session.commit()
            return make_response(jsonify({'task': 'delete a message', 'status': 'success'}), 200)
        return make_response(jsonify({'task': 'delete a message', 'status': 'failed'}), 401)
    return make_response(jsonify({'task': 'get or post message', 'status': 'failed', 'reason': 'user not authenticated'}))  # add status


if __name__ == '__main__':
    app.run(debug=True)
