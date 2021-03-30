from apscheduler.schedulers.background import BackgroundScheduler
from .models import AccessRequest, RegistrationRequest, User
from . import db
from flask import current_app
from datetime import datetime, timedelta

# in seconds
CRON_INTERVAL = 60

def is_expired(start, now, expire = 300):
    min_start = now - timedelta(seconds= expire)
    return start < min_start

def cronjob():
    """Background cron-job which should run periodly."""

    # with db.app.app_context():
    now = datetime.now()
    min_start_access_request = now - timedelta(seconds=AccessRequest.EXPIRE)
    min_start_registration_request = now - timedelta(seconds = RegistrationRequest.EXPIRE)
    AccessRequest.query.filter(is_expired(AccessRequest.start_at, now, AccessRequest.EXPIRE)).delete()
    RegistrationRequest.query.filter(is_expired(RegistrationRequest.start_at, now, RegistrationRequest.EXPIRE)).delete()
    db.session.commit()
    # print(RegistrationRequest.query.count(), AccessRequest.query.count())

print('STARTING CRONJOB!')
print(current_app)

scheduler = BackgroundScheduler()
# start cronjob
job = scheduler.add_job(cronjob, 'interval', seconds=CRON_INTERVAL)
scheduler.start()

