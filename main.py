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
#
import webapp2
import os
import jinja2
import re
import logging
import hashlib
import hmac
import string
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


# Databases
class Article(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	edited = db.DateTimeProperty(auto_now = True)
	likes = db.IntegerProperty(default = 0)
	user = db.StringProperty(required = True)


class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)
	created = db.DateTimeProperty(auto_now_add = True)


class Comment(db.Model):
	article_id = db.IntegerProperty(required = True)
	user = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)


class Like(db.Model):
	article_id = db.IntegerProperty(required = True)
	user = db.StringProperty(required = True)


# Super Class for all handlers
class Handler(webapp2.RequestHandler):

	# Checks if the user is logged in
	def isLogged(self):
		cookie = self.request.cookies.get('username')
		if cookie and check_secure_val(cookie):
			return cookie.split("|")[0]

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	# Sets the cookie for login and redirects to welcome page
	def login(self, user):
		val = make_secure_val(str(user))
		self.response.headers.add_header("Set-Cookie", r"username=%s; Path=/" %val)
		self.redirect("/welcome")

# Handler sub classes


# Front page handler, shows the last 10 articles
class MainHandler(Handler):
	def get(self):
		articles = db.GqlQuery("""SELECT * FROM Article 
			ORDER BY created DESC LIMIT 10""")
        self.render("blog.html", isLogged = self.isLogged(), 
        	articles = articles)


# Sign up page handler, shows a sign up form if user is not logged in
class SignUpHandler(Handler):
	def get(self):
		if(self.isLogged()):
			self.redirect("/")
		else:
			self.render("signup.html", user_error = "", pass_error = "",
						pass2_error = "", email_error = "")

	def post(self):
		user = self.request.get("username")
		pass1 = self.request.get("password")
		pass2 = self.request.get("verify")
		email = self.request.get("email")

		# Checking every field
		user_ok  = checkUser(user)
		pass_ok  = checkPass(pass1)
		pass2_ok = checkPass2(pass1, pass2)
		email_ok = checkEmail(email)

		# Checking if all fields are ok
		if(user_ok and pass_ok and pass2_ok and email_ok):

			# Checking if the user already exists
			existing_user = db.GqlQuery("""SELECT * FROM User 
				WHERE username=\'""" + user + "\'").get()
			if(existing_user):
				user_error = "There already is a user with that name."
				self.render("signup.html", user_error = user_error, email = email)
				return
			else:
				# Signing up
				salt = make_salt()
				password = make_pw_hash(SECRET, pass1, salt)
				if(email):
					user_to_be_added = User(username = user, password = password,
											email = email)
				else:
					user_to_be_added = User(username = user, password = password)
				db.put(user_to_be_added)
				self.login(user)

		# Initialising / setting error messages
		if user_ok:
			user_error = ""
		else:
			user_error = user_err_string
			user = ""

		if pass_ok:
			if pass2_ok:
				pass2_error = ""
			else:
				pass2_error = pass2_err_string
			pass_error = ""
		else:
			pass_error = pass_err_string
			pass2_error = ""

		if email_ok:
			email_error = ""
		else:
			email_error = email_err_string
			email = ""

		self.render("signup.html", user_error = user_error, 
			pass_error = pass_error, pass2_error = pass2_error, 
			email_error = email_error, user = user, email = email)


# Log in handler, shows a form if the user is not logged in
class LoginHandler(Handler):
	def get(self):
		if(self.isLogged()):
			self.render("error.html", error = "You are already logged in!")
		else:
			self.render("login.html")

	def post(self):
		user = self.request.get("username")
		password = self.request.get("password")

		# Checking if both fields are not empty
		if user and password:

			# Checking if the username and password match
			db_users = db.GqlQuery("SELECT * FROM User WHERE username=\'" + user + "\'")
			if(db_users.get()):
				db_user = db_users[0]
				if valid_pw(SECRET, password, db_user.password):
					self.login(user)
				else:
					self.render("login.html", user=user, 
						error="The user and password do not match")	
			else:  # The user does not exist
				self.render("login.html", user=user, 
					error="The user and password do not match")
		else:
			self.render("login.html", user=user, 
				error="Please enter a username and a password")


# Log out handler, logs the user out if he is logged in
class LogoutHandler(Handler):
	def get(self):
		if self.isLogged():
			self.response.headers.add_header("Set-Cookie", "username=; Path=/")
			self.redirect("/signup")
		else:
			self.render("error.html", error = "You need to be logged in to log out!")


# Displays a welcome message if the user is logged in
class WelcomeHandler(Handler):
	def get(self):
		username = self.isLogged()
		if username:
			self.render("welcome.html", isLogged = True, username = username)
		else:
			self.redirect("/signup")


# Handler for creating a new post, displays the form is the user is logged in
class NewPostHandler(Handler):
	def get(self):
		if self.isLogged():
			self.render("newpost.html", isLogged=True)
		else:
			self.redirect("/signup")

	def post(self):
		title = self.request.get("subject")
		content = self.request.get("content")
		username = self.isLogged()
		if title and content:
			if username:
				a = Article(title=title, content=content, user=username)
				a.put()
				self.redirect("/posts/"+str(a.key().id()))
			else:
				self.redirect("/signup")	
		else:
			error = "We need both a title and some content!"
			self.render("newpost.html", isLogged = True, title=title, 
						content=content, error=error)


# Shows a particular post
class PostHandler(Handler):
	def get(self, id):
		article = Article.get_by_id(int(id))
		comments = db.GqlQuery("SELECT * FROM Comment WHERE article_id=" + 
			str(int(id)) + " ORDER BY created DESC")
		self.render("post.html", isLogged = self.isLogged(), 
					article=article, comments = comments)

# Post manipulation handlers


# Handler for deleting a post
class DeletePostHandler(Handler):
	def get(self, id):
		article = Article.get_by_id(int(id))
		username = self.isLogged()
		if (username and article.user==username):
			article.delete()
			self.redirect("/")
		else:
			self.render("error.html", error="You do not have acces to this action!")


# Handler for editing a post
class EditPostHandler(Handler):
	def get(self, id):
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if username:
			if article.user==username:
				self.render("editpost.html", isLogged=True, article=article, 
					title=article.title, content = article.content)
			else:
				self.render("error.html", error="You do not have acces to this action!")
		else:
			self.redirect("/signup")

	def post(self, id):
		title = self.request.get("subject")
		content = self.request.get("content")
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if title and content:
			if username:
				if article.user==username:
					article.title = title
					article.content = content
					article.put()
					self.redirect("/posts/"+id)
				else:
					self.render("error.html", error="You do not have acces to this action!")
			else:
				self.redirect("/signup")
		else:
			error = "We need both a title and some content!"
			self.render("editpost.html", isLogged = True, title=title, 
						content=content, article=article, error=error)


# Handler for commenting on a post
class CommentPostHandler(Handler):
	def get(self, id):
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if username:
			self.render("commentpost.html", isLogged=True, article=article)
		else:
			self.redirect("/signup")

	def post(self, id):
		content = self.request.get("content")
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if content:
			if username:
				comment = Comment(content=content, user=username, article_id=int(id))
				comment.put()
				self.redirect("/posts/"+id)
			else:
				self.redirect("/signup")
		else:
			error = "We need some content!"
			self.render("commentpost.html", error=error, isLogged=True, article=article)


# Handler for liking a post
class LikePostHandler(Handler):
	def get(self, id):
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if username:
			if not article.user==username:
				like = db.GqlQuery("SELECT * FROM Like WHERE article_id=" + 
					str(id) + " AND user=\'" + username + "\'")
				if(like.get()):
					like[0].delete()
					article.likes = article.likes - 1
					article.put()
					self.redirect("/posts/" + id)
				else:
					like = Like(article_id=int(id), user=username)
					like.put()
					article.likes = article.likes + 1
					article.put()
					self.redirect("/posts/"+id)
			else:
				self.render("error.html", error="You can not like your own article!")
		else:
			self.redirect("/signup")

	def post(self, id):
		title = self.request.get("subject")
		content = self.request.get("content")
		username = self.isLogged()
		article = Article.get_by_id(int(id))
		if title and content:
			if username:
				if article.user==username:
					article.title = title
					article.content = content
					article.put()
					self.redirect("/posts/"+id)
				else:
					self.render("error.html", error="You do not have acces to this action!")
			else:
				self.redirect("/signup")	
		else:
			error = "We need both a title and some content!"
			self.render("editpost.html", title=title, content=content, error=error)


# Comment manipulation handlers

# Editing a comment handler; aid is article id; cid is comment id
class EditCommentHandler(Handler):
	def get(self, aid, cid): 
		username = self.isLogged()
		article = Article.get_by_id(int(aid))
		comment = Comment.get_by_id(int(cid))
		if username:
			if comment.user==username:
				self.render("editcomment.html", isLogged=True, article=article, 
					comment = comment)
			else:
				self.render("error.html", error="You do not have acces to this action!")
		else:
			self.redirect("/signup")

	def post(self, aid, cid):
		content = self.request.get("content")
		username = self.isLogged()
		article = Article.get_by_id(int(aid))
		comment = Comment.get_by_id(int(cid))
		if content:
			if username:
				if comment.user==username:
					comment.content = content
					comment.put()
					self.redirect("/posts/"+aid)
				else:
					self.render("error.html", error="You do not have acces to this action!")
			else:
				self.redirect("/signup")
		else:
			error = "The comment needs some content!"
			self.render("editcomment.html", isLogged = True, article=article, 
				comment=comment, error=error)


# Deleting a comment handler; aid is article id; cid is comment id
class DeleteCommentHandler(Handler):
	def get(self, aid, cid):
		article = Article.get_by_id(int(aid))
		comment = Comment.get_by_id(int(cid))
		username = self.isLogged()
		if (username and comment.user==username):
			comment.delete()
			self.redirect("/posts/"+aid)
		else:
			self.render("error.html", error="You do not have acces to this action!")


# For checking on signup


def checkUser(user):
	user2 = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return user2.match(user)


def checkPass(pass1):
	pass2 = re.compile(r"^.{3,20}$")
	return pass2.match(pass1)


def checkPass2(pass1, pass2):
	return pass2 == pass1


def checkEmail(email):
	email2 = re.compile(r"^[\S]+@[\S]+.[\S]+$")
	return email2.match(email) or email==""

# Strings

user_err_string = "That is not a valid username"
pass_err_string = "That is not a vald password"
pass2_err_string = "Your passwords did not match"
email_err_string = "That is not a valid email"
SECRET = "youcanotHACKZmepeople"

# For cookie


def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return val

# For passwords

def make_salt():
	return "".join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=make_salt()):
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    split = h.split(",")
    hash = split[0]
    salt = split[1]

    logging.warning("h =" + h)
    logging.warning("make = " + make_pw_hash(name, pw, salt))
    return h == make_pw_hash(name, pw, salt)
    
# Misc

class TimesVisitedCookieHandler(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		visits = 0
		visit_cookie_str = self.request.cookies.get('visits')
		if(visit_cookie_str):
			cookie_val = check_secure_val(visit_cookie_str)
			if cookie_val:
				visits = int(cookie_val)
		
		visits += 1

		new_cookie_val = make_secure_val(str(visits))

		self.response.headers.add_header("Set-Cookie", "visits=%s" %new_cookie_val)

		if visits > 15:
			self.write("You are the best ever!")
		else:
			self.write("You have been here %s times" % visits)


app = webapp2.WSGIApplication([ ('/', MainHandler), 
    							('/newpost', NewPostHandler), 
    							('/posts/(\d+)/like', LikePostHandler), 
    							('/posts/(\d+)/comment', CommentPostHandler), 
    							('/posts/(\d+)/edit', EditPostHandler), 
    							('/posts/(\d+)/delete', DeletePostHandler), 
    							('/posts/(\d+)/comm/(\d+)/delete', DeleteCommentHandler), 
    							('/posts/(\d+)/comm/(\d+)/edit', EditCommentHandler), 
    							('/posts/(\d+)', PostHandler), 
    							('/timesvisited', TimesVisitedCookieHandler),
    							("/signup", SignUpHandler), 
    							("/welcome", WelcomeHandler), 
    							("/login", LoginHandler),
    							("/logout", LogoutHandler)
], debug=True)