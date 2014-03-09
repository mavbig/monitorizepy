# LICENSE
#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# IMPORTS
from validate import valid_username, valid_email, valid_password, check_secure_val,\
    make_secure_val, make_pw_hash, valid_pw, users_key
import webapp2
from google.appengine.ext import webapp
import os
import jinja2
import logging
from google.appengine.ext import db

# TEMPLATE SETTINGS
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class BaseHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        params['user'] = self.user
        #logging.info(params)
        if self.user:
            params['username'] = self.user.name
            logging.info(params['username'])
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kwargs):
        self.response.out.write(self.render_str(template, **kwargs))

    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie','%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *args, **kwargs):
        webapp2.RequestHandler.initialize(self, *args, **kwargs)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        #if self.user:
            #logging.info(self.user.name)



class Rot13(BaseHandler):
    def get(self):
        self.render('rot13.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13.html', text = rot13)

class Signup(BaseHandler):
    def get(self):
        self.render('signup.html')

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username!"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That's not a valid password!"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Passwords do not match"

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email!"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *args, **kwargs):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That User Already Exists'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = "Invalid Login"
            self.render('login.hmtl', error = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/login')

class Blog(BaseHandler):
    def get(self):
        blogentries = db.GqlQuery("SELECT * FROM Blogentry ORDER BY created DESC LIMIT 10")
        self.render('blog.html', blogentries=blogentries)

class Newpost(BaseHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        have_error = False
        blogtitle = self.request.get('blogtitle')
        blogtext = self.request.get('blogtext')

        params = dict(blogtitle = blogtitle,
                      blogtext = blogtext)
        if not blogtitle:
            params['error_blogtitle'] = "Oh Come on, Please enter a title"
            have_error = True

        if not blogtext:
            params['error_blogtext'] = "Please enter a text"
            have_error = True

        if have_error:
            self.render('newpost.html', **params)
        else:
            b = Blogentry(title = blogtitle, text = blogtext)
            b.put()
            self.redirect('/blog/%s' % str(b.key().id()))

class Blogredirect(BaseHandler):
    def get(self, post_id):
        blogkey = db.Key.from_path('Blogentry', int(post_id))
        post = db.get(blogkey)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class Blogentry(db.Model):
    title = db.StringProperty()
    text = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent= users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent= users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

def main():
    logging.getLogger().setLevel(logging.DEBUG)
    webapp.util.run_wsgi_app(app)

if __name__ == '__main__':
    main()

app = webapp2.WSGIApplication([
    #('/', MainHandler),
    #('/thanks', Thankshandler),
    ('/rot13', Rot13),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/blog/([0-9]+)', Blogredirect),
    ('/blog/?', Blog),
    ('/blog/newpost', Newpost),
    ('/login', Login),
    ('/logout', Logout),
], debug=True)
