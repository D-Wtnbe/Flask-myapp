from mixer.backend.flask import mixer
from mixer.backend.sqlalchemy import Mixer
from app import *
mixer.init_app(app)

def seed():
    for i in range(1000):
        user = mixer.blend(User)

if __name__ == "__main__":
        seed()
