from flask import Flask
from .api import api
from .tasks import celery as celery_app
import os

def create_app():
    app = Flask(__name__)
    
    # Celery configuration
    app.config['CELERY_BROKER_URL'] = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    app.config['CELERY_RESULT_BACKEND'] = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
    
    celery_app.conf.update(app.config)
    
    app.register_blueprint(api)
    
    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)