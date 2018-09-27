#!/usr/bin/env python2.7

import json
import webapp2
import uuid
from google.appengine.ext import ndb
from lib.bcrypt import bcrypt
from datetime import datetime
from datetime import timedelta
import jinja2
import os
from google.appengine.api import urlfetch
import urllib
import base64


JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)

theNonce = str(uuid.uuid4())


class Secret(ndb.Model):
    name = ndb.StringProperty()
    value = ndb.StringProperty()


class Init(webapp2.RequestHandler):
    @ndb.transactional
    def get(self):
        key = ndb.Key(Secret, "oidc_client")
        if key.get():
            return self.response.write("Already exists")
        Secret(key=key, name=key.id(), value="").put()
        self.response.write("Success")


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

        for event in ModelEvent.query(ancestor=_root_key).order(-ModelEvent.date).fetch():
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
        theState = str(uuid.uuid4())
        self.response.set_cookie("state", theState)
        # self.response.write(open("login.html").read())

        # theNonce = str(uuid.uuid4())

        template_values = {
            'state': theState,
            'nonce': theNonce
        }
        template = JINJA_ENVIRONMENT.get_template('login.html')
        self.response.write(template.render(template_values))


class DisplayRegistration(webapp2.RequestHandler):
    def get(self):
        self.response.write(open("registration.html").read())


class OidcAuth(webapp2.RequestHandler):
    def get(self):
        # `status` and `code` from the url
        theCode = self.request.params['code']
        theState = self.request.params['state']

        # Cookie state
        current_state = self.request.cookies.get("state")

        # Client secret got from the datastore
        client_secret = ndb.Key(Secret, "oidc_client").get().value

        if (theState != current_state):
            self.response.write("State does NOT match!!!")
        else:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            request_params = {
                "code": theCode,
                "client_id": "625404489207-0iodv0kr884meqn2fn2961702u93usut.apps.googleusercontent.com",
                "client_secret": client_secret,
                "redirect_uri": 'https://robinhung-03.appspot.com/oidcauth',
                "grant_type": "authorization_code"
            }
            form_data = urllib.urlencode(request_params)
            result = urlfetch.fetch(
                url="https://www.googleapis.com/oauth2/v4/token",
                payload=form_data,
                method=urlfetch.POST,
                headers=headers
            )

            jwt = result.content
            # self.response.write(jwt)
            jwt_string = json.loads(jwt)

            _, body, _ = jwt_string['id_token'].split('.')
            while len(body) % 4:
                body += '='
            claims = base64.b64decode(body)
            cc = json.loads(claims)

            user_email = cc['email']
            user_password = cc['sub']

            # Check nonce
            if cc['nonce'] != theNonce:
                self.response.write("Nonce does NOT match!")

            else:

                rUser = RegisteredUser(
                    key=ndb.Key("RegisteredUser", user_email),
                    username=user_email,
                    hashedPassword=bcrypt.hashpw(user_password, bcrypt.gensalt()))
                rUser.put()

                tok = str(uuid.uuid4())
                exp = datetime.now() + timedelta(hours=1)
                session = Session(
                    key=ndb.Key("Session", tok),
                    token=tok,
                    username=user_email,
                    expiration=exp
                )
                session.put()

                self.response.set_cookie("s", tok)

                self.redirect('/')


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
    ('/migrate', Migration),
    ('/init', Init),
    ('/oidcauth', OidcAuth)
], debug=True)
