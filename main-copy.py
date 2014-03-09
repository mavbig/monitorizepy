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

from validate import valid_day, valid_month, valid_year, escape_html, valid_username, valid_email, valid_password
import webapp2

form = """
<form method="post">
    What is your birthday?
    <br>
    <label> Month<input type="text" name="month" value="%(month)s"></label>
    <label> Day<input type="text" name="day" value="%(day)s"></label>
    <label> Year<input type="text" name="year" value="%(year)s"></label>
    <div style="color: red">%(error)s</div>
    <br>
    <br>
    <input type="submit">
</form>
"""

form2 = """
<form method="post">
    <textarea name="text">%(rottext)s</textarea>
    <br>
    <input type="submit">
</form>
"""

form3 = """
<form method="post">
    Signup
    <br>
    <label>Username<input type="text" name="username" value="%(username)s"></label>
    <br>
    <label>Password<input type="text" name="password"></label>
    <br>
    <label>Verify<input type="text" name="verify"></label>
    <br>
    <label>E-Mail<input type="text" name="email" value="%(email)s"></label>
    <br>
    <input type="submit">
    <br>
    <div style="color: red">%(error)s</div>
</form>
"""




class MainHandler(webapp2.RequestHandler):
    def write_form(self, error="", month="", day="", year=""):
        self.response.out.write(form % {"error": escape_html(error),
                                        "month": escape_html(month),
                                        "day": escape_html(day),
                                        "year": escape_html(year)})

    def get(self):
        self.write_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_form("That doesn't look valid boy!", user_month, user_day, user_year)
        else:
            self.redirect("/thanks")

class Thankshandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Thanks! That's a totally valid day!")

class RotHandler(webapp2.RequestHandler):
    def get(self, rottext=""):
        self.response.out.write(form2  % {"rottext": rottext})

    def post(self):
        rottext = self.request.get('text')
        rottext = escape_html(rottext.encode('rot13'))
        self.response.out.write(form2 % {"rottext": rottext})

class SignupHandler(webapp2.RequestHandler):
    def write_form3(self, error="", username="", email=""):
        self.response.out.write(form3 % {"error": escape_html(error),
                                         "username": escape_html(username),
                                         "email": escape_html(email)})

    def get(self):
        self.write_form3()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        if  ((valid_username(username)) != None and (valid_password(password) != None) and (valid_email(email) != None)):
            if password == verify:
                self.redirect('/welcome')
            else:
                self.write_form3("That's not good bro!", username, email)



class WelcomeHandler(webapp2.RequestHandler):
    def get(self):
        user = self.request.get('username')
        self.response.out.write("Welcome Mr. %s" % user)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/thanks', Thankshandler),
    ('/rot13', RotHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler,)
], debug=True)
