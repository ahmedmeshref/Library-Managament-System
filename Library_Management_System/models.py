from flask_login import UserMixin

from Library_Management_System import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    book = db.relationship("Lend", backref="lended", lazy=True)
    admin = db.Column(db.Boolean, default=False)
    librarian = db.Column(db.Boolean, default=False)


class Book(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    author = db.Column(db.String(255))
    description = db.Column(db.Text)
    total_quantity = db.Column(db.Integer, default=0)
    available_quantity = db.Column(db.Integer, default=0)
    rented_count = db.Column(db.Integer, default=0)

class Lend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    book_id = db.Column(
        db.Integer, db.ForeignKey("book.id"), nullable=False
    )
    date_issued = db.Column(db.DateTime(), default=None)
    date_added = db.Column(db.DateTime())
    date_return = db.Column(db.DateTime(), default=None)
    lent_state = db.Column(db.Boolean, default=False)