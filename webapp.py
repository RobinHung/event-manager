#!/usr/bin/env python2.7

import json
import webapp2
import uuid
from google.appengine.ext import ndb
from lib.bcrypt import bcrypt
from datetime import datetime
from datetime import timedelta


class ModelEvent(ndb.Model):
    name = ndb.StringProperty()
    date = ndb.StringProperty()


class Session(ndb.Model):
    token = ndb.StringProperty()
    username = ndb.StringProperty()
    expiration = ndb.DateTimeProperty()


class RegisteredUser(ndb.Model):
    username = ndb.StringProperty()
    hashedPassword = ndb.StringProperty()


_root_key = ndb.Key('Entities', 'root')


class ListEvents(webapp2.RequestHandler):
    def get(self):
        # @dev: when adding data for migration, following should be commented!!
        tok = self.request.cookies.get("s")
        session = ndb.Key("Session", tok).get()
        current_username = session.username
        user = ndb.Key("RegisteredUser", current_username).get()

        if tok:
            # self.response.write(json.dumps({
            #     'events': [dict(name=val.name, date=val.date, id=val.key.urlsafe())
            #                for val in ModelEvent.query(ancestor=user.key).iter()],
            #     'error': None,
            # }))

            self.response.write(json.dumps({
                'events': [dict(name=val.name, date=val.date, id=val.key.urlsafe())
                           for val in ModelEvent.query(ancestor=user.key).fetch()],
                'error': None,
            }))
        else:
            self.response.write(json.dumps({
                'events': [dict(name=val.name, date=val.date, id=val.key.urlsafe())
                           for val in ModelEvent.query(ancestor=_root_key).iter()],
                'error': None,
            }))

        # @dev: only when adding migration data should the following be uncommented
        # self.response.write(json.dumps({
        #     'events': [dict(name=val.name, date=val.date, id=val.key.urlsafe())
        #                for val in ModelEvent.query(ancestor=_root_key).iter()],
        #     'error': None,
        # }))


class DeleteEvent(webapp2.RequestHandler):
    def delete(self, id):
        k = ndb.Key(urlsafe=id)
        k.delete()


class PostEvent(webapp2.RequestHandler):
    def post(self):
        data = json.loads(self.request.body)

        # @dev: when adding data to test migration, following should be commented
        tok = self.request.cookies.get("s")
        session = ndb.Key("Session", tok).get()
        current_username = session.username
        user = ndb.Key("RegisteredUser", current_username).get()

        if tok:
            ev = ModelEvent(parent=user.key,
                            name=data["name"], date=data["date"])
            ev.put()
        else:
            ev = ModelEvent(parent=_root_key,
                            name=data["name"], date=data["date"])
            ev.put()

        # @dev: When adding migrated data, the following should be uncommented!
        # ev = ModelEvent(parent=_root_key, name=data["name"], date=data["date"])
        # ev.put()


class RegisterUser(webapp2.RequestHandler):
    def post(self):
        data = json.loads(self.request.body)
        username = data["username"]
        password = data["password"]

        rUser = RegisteredUser(
            key=ndb.Key("RegisteredUser", username),
            username=username,
            hashedPassword=bcrypt.hashpw(password, bcrypt.gensalt()))
        rUser.put()
        print "update datastore!"

        tok = str(uuid.uuid4())
        exp = datetime.now() + timedelta(hours=1)
        session = Session(
            key=ndb.Key("Session", tok),
            token=tok,
            username=username,
            expiration=exp
        )
        session.put()
        print "session update in db"

        self.response.set_cookie("s", tok)
        print "cookie set!!!"

        self.response.write(
            json.dumps(dict(redirect_url='/', status='success')))


class Login(webapp2.RequestHandler):
    def post(self):
        login_data = json.loads(self.request.body)

        login_username = login_data["username"]
        login_password = login_data["password"]

        user = ndb.Key("RegisteredUser", login_username).get()
        print user

        if not user:
            self.response.write(json.dumps({'status': 'User doesn\'t exist.'}))
            print "NOOOOO this user!"
            return

        if user.hashedPassword != bcrypt.hashpw(login_password, user.hashedPassword):
            self.response.write(json.dumps(
                {'status': 'Wrong user password, please try again.'}))
            print "WRONG PASSWORD!"
            return

        tok = str(uuid.uuid4())
        exp = datetime.now() + timedelta(hours=1)
        session = Session(
            key=ndb.Key("Session", tok),
            token=tok,
            username=login_username,
            expiration=exp
        )
        session.put()
        print session
        print "You should be LOGGED IN!"

        self.response.set_cookie("s", tok)
        print "cookie get!"

        self.response.write(json.dumps({
            "redirect_url": "/",
            "status": "success"
        }))


class Logout(webapp2.RequestHandler):
    def post(self):
        tok = self.request.cookies.get("s")
        if tok:
            ndb.Key("Session", tok).delete()
            self.response.delete_cookie("s")

        print "cookie cleared!"

        self.response.write(json.dumps(
            dict(redirect_url="/", status="success")
        ))

        print "redirection should happened :)"


class Migration(webapp2.RequestHandler):
    def post(self):
        tok = self.request.cookies.get("s")
        session = ndb.Key("Session", tok).get()
        current_username = session.username
        user = ndb.Key("RegisteredUser", current_username).get()
        # print current_username
        # print session
        # print session.key
        # print user
        # print user.key

        for event in ModelEvent.query(ancestor=_root_key).order(-ModelEvent.date).fetch():
            # print event
            # print event.key
            # if event.key == _root_key:
            #     migrated_event = ModelEvent(
            #         parent=user.key, name=event.name, date=event.date)
            #     migrated_event.put()
            migrated_event = ModelEvent(
                parent=user.key, name=event.name, date=event.date)
            migrated_event.put()
            event.key.delete()


class Redirect(webapp2.RequestHandler):
    def get(self):
        self.response.write(json.dumps({
            "redirect_url": "/registration",
            "status": "success"
        }))


class Home(webapp2.RequestHandler):
    def get(self):
        # @dev: uncommented the following to see mainpage without login
        tok = self.request.cookies.get("s")
        # No session cookie!
        if not tok:
            print "NO COOKIE :("
            return self.redirect("/loginpage")

        print "GET THE COOKIE"
        print _root_key
        self.response.write(open("index.html").read())


class DisplayLogin(webapp2.RequestHandler):
    def get(self):
        self.response.write(open("login.html").read())


class DisplayRegistration(webapp2.RequestHandler):
    def get(self):
        self.response.write(open("registration.html").read())


app = webapp2.WSGIApplication([
    ('/', Home),
    ('/events', ListEvents),
    ('/event/(.*)', DeleteEvent),
    ('/event', PostEvent),
    ('/loginpage', DisplayLogin),
    ('/registration', DisplayRegistration),
    ('/register', RegisterUser),
    ('/login', Login),
    ('/redirect', Redirect),
    ('/logout', Logout),
    ('/migrate', Migration)
], debug=True)
