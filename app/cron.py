from apscheduler.schedulers.background import BackgroundScheduler
from app import app,db,logging
from config import Config
from app.models import EnrollFile, EmailValidator
from datetime import date,timedelta,datetime
from sqlalchemy import update
import re
import string

logging.getLogger('accounts-cron').addHandler(logging.StreamHandler())
logger = logging.getLogger('accounts-cron')

app.config.from_object(Config)

def EnrollLoad():
    enroll_file = app.config['ENROLL_FILE']

    enroll_file_uins = []

    entry_entered = 0
    entry_removed = 0
    entry_updated = 0
    entry_skipped = 0

    logger.info('Starting import at: %s' % datetime.now())
    in_f = open(enroll_file, 'r')

    for line in in_f:
        user_info = line.split(':')
        reg_class=user_info[0]
        full_name=user_info[2]
        names = full_name.translate(str.maketrans("", "", string.punctuation)).split(' ')
        lname = names[0].strip()
        fname = names[1].strip()
        uin=user_info[3].strip()
        oduemail=user_info[4].lower()

        #Add to an array of all UINs for future use
        enroll_file_uins.append(uin)

        #Remove any letters in the class field so it can be turned into an INT
        reg_class = re.sub(r'[A-Z]+', '', reg_class, re.I)

        grad = False
        if int(reg_class) > 500:
            grad = True
            
        this_user_entry = EnrollFile(firstname=fname, lastname=lname, uin=uin, email=oduemail, grad=grad)
        uin_filter =  EnrollFile.uin == uin

        #If the UIN doesnt already exist in the DB, add it.
        if db.session.query(EnrollFile).filter(uin_filter).count() < 1:
            db.session.add(this_user_entry)
            db.session.commit()
            entry_entered += 1
            continue
            
        existing_user_entry = EnrollFile.query.filter(uin_filter).first()

        #If the already-existing user entry is not a grad, and this new entry IS a grad - Update.
        if existing_user_entry.grad != True & this_user_entry.grad == True:

            update_user = EnrollFile.query.filter_by(uin=uin).first()
            update_user.grad = True
            db.session.commit()

            entry_updated += 1
            continue
        else:
            entry_skipped += 1
            continue

    in_f.close()

    #This section removes rows from the database if they no longer appear in an enroll file.
    db_uins = []
    db_entries = EnrollFile.query.all()
    for entry in db_entries:
        db_uins.append(entry.uin)

    for db_uin in db_uins:
        if db_uin not in enroll_file_uins:
            db.session.query(EnrollFile).filter(EnrollFile.uin == db_uin).delete()
            db.session.commit()
            entry_removed += 1
            

    logger.info('-Import finished at: %s' % datetime.now())
    logger.info('--New Enteries Added: %s' % entry_entered)
    logger.info('--Entries Updated: %s' % entry_updated)
    logger.info('--Old Enteries Deleted: %s' % entry_removed)

    del db_uins[:]
    del enroll_file_uins[:]



sched = BackgroundScheduler(daemon=True)
sched.add_job(EnrollLoad,'interval',minutes=60)
sched.start()