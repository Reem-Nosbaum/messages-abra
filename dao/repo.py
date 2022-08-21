from app import Users
from app import Messages
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
import uuid


class Repo:

    @staticmethod
    def get_user_by_username(username: str) -> list[Users]:
        return Users.query.filter_by(username=username).all()

    @staticmethod
    def create_new_user(username: str, password: str) -> None:
        hashed_password = generate_password_hash(password, method='sha256')  # hashing the password
        new_user = Users(public_id=str(uuid.uuid4()), username=username, password=hashed_password)
        db.session.add(new_user)  # adding the new user to the db
        db.session.commit()
