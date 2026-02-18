import os

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from .api import api
from .certificate import certificate_bp
from .tasks import celery as celery_app


def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config["JWT_SECRET_KEY"] = "fac0dbd5"
    jwt = JWTManager(app)

    app.config["CELERY_BROKER_URL"] = os.getenv(
        "CELERY_BROKER_URL", "redis://localhost:6379/0"
    )
    app.config["CELERY_RESULT_BACKEND"] = os.getenv(
        "CELERY_RESULT_BACKEND", "redis://localhost:6379/0"
    )

    celery_app.conf.update(app.config)

    app.register_blueprint(api)
    app.register_blueprint(certificate_bp)

    return app
