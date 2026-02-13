from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

user_badges = db.Table(
    'user_badges',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('badge_id', db.Integer, db.ForeignKey('badge.id'))
)

class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    color = db.Column(db.String(20), default="#5865f2")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    ban_reason = db.Column(db.String(255), nullable=True)
    rank = db.Column(db.String(20), default=None)
    badges = db.relationship("Badge", secondary=user_badges, backref="users")

    # --- НОВЫЕ ПОЛЯ ---
    marital_status = db.Column(db.String(50), nullable=True)  # Женат / Не женат
    gender = db.Column(db.String(50), nullable=True)          # Пол
    address = db.Column(db.String(255), nullable=True)
    telegram = db.Column(db.String(100), nullable=True)
    discord = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), nullable=True)


class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)




class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_pinned = db.Column(db.Boolean, default=False)


    user = db.relationship('User', backref='messages')


class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])


