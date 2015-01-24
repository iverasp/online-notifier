import json
import urllib2
import time
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///app.db')
Base = declarative_base()
session = sessionmaker()
session.configure(bind=engine)
s = session()

class Events(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True)
    event_id = Column(Integer, nullable=False)
    name = Column(String(250), nullable=False)
    reg_date = Column(DateTime, nullable=False)

    def __init__(self, event_id, name, reg_date):
        self.name = name
        self.reg_date = reg_date

def main():
    response = urllib2.urlopen(
    'https://online.ntnu.no/api/v0/events/?event_end__gte='
    + time.strftime('%Y-%m-%d')
    + '&order_by=event_start&limit=10&format=json'
    )
    data = json.load(response)
    events = {}
    for d in data['events']:
        if d['attendance_event'] is not None:
            events[int(d['id'])] = {'name': d['title'], 'reg_start': d['attendance_event']['registration_start']}
            print d['attendance_event']['registration_start']
    for key, value in events.iteritems():
        lol = s.query(Events).filter(Events.event_id == key)
        print lol
        print key, value

if __name__=='__main__':
    main()
