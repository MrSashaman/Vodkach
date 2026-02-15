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


server_members = db.Table(
    'server_members',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('server_id', db.Integer, db.ForeignKey('server.id'))
)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(255), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    members = db.relationship("User", secondary=server_members, backref="servers")


class ServerMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))

    user = db.relationship("User")


class ServerInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))
    inviter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    invited_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    server = db.relationship("Server")
    inviter = db.relationship("User", foreign_keys=[inviter_id])
    invited = db.relationship("User", foreign_keys=[invited_id])


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))
    server = db.relationship("Server", backref="channels")


class ChannelMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))

    user = db.relationship("User")
    channel = db.relationship("Channel", backref="messages")

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emoji = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'))


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
    status = db.Column(db.String(20), default="online")

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



