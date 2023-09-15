from database import db

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(255), unique=True, nullable=False)
    
    def __repr__(self):
        return f'<Role {self.nama}>'