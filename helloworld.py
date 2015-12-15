import webapp2
import jinja2
import os
import time
import hmac
import random
import string
import hashlib
import json
import logging
from google.appengine.api import memcache
from google.appengine.ext import db
JINJA_ENVIRONMENT= jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)+"/templates"), autoescape=True)

SECRET="XXXXXXX"
months = ['January',
		  'February',
		  'March',
		  'April',
		  'May',
		  'June',
		  'July',
		  'August',
		  'September',
		  'October',
		  'November',
		  'December']

month_abbvs = dict((m[:3].lower(),m) for m in months)
	
def rot13(word):
	length=len(word)
	k=13
	result=''
	for i in range(length):
		target=word[i]
		lower=target.islower()
		target=target.lower()
		if(ord(target)>96 and ord(target)<123):
			ascii=ord(target)
			ascii+=k
			if(ascii>122):
				ascii=96+ascii%122
			target=chr(ascii)
			#print(lower)
			if(not lower):
				target=target.upper()
		result+=target
	return result

def valid_month(month):
	if month:
		short_month=month[:3].lower()
		return month_abbvs.get(short_month)

def valid_day(day):
	if(day.isdigit()):
		if(int(day)>0 and int(day)<32):
			return int(day)

def valid_year(year):
	if(year.isdigit()):
		year=int(year)
		if(year>1900 and year<2020):
			return year

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val=h.split('|')[0]
    if make_secure_val(val)==h:
        return val

def make_pw_hash(name, pw,salt=''):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    ###Your code here
    return h==make_pw_hash(name,pw,h.split('|')[1])

class Article(db.Model):
	title=db.StringProperty(required=True)
	content=db.TextProperty(required=True)
	created=db.DateTimeProperty(auto_now_add=True)

class User(db.Model):
	name=db.StringProperty(required=True)
	password=db.StringProperty(required=True)
	email=db.StringProperty(required=False)
	joined=db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
	def write(self,*a,**kw):
		self.response.out.write(*a,**kw)

	def render_str(self, template, **params):
		t=JINJA_ENVIRONMENT.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class MainPage(Handler):
	def write_form(self,error="",month="",day="",year=""):
		self.render("birthday.html",error=error,month=month,day=day,year=year)
		
	def get(self):
		#self.response.headers['Content-Type'] = 'text/plain'
		self.write_form()

	def post(self):
		user_month=self.request.get('month')
		user_day=self.request.get('day')
		user_year=self.request.get('year')
		month=valid_month(user_month)
		day=valid_day(user_day)
		year=valid_year(user_year)
		if not(month and day and year):
			self.write_form("Invalid date!",user_month,user_day,user_year)
		else:
			self.redirect('/thanks')

class ThanksHandler(webapp2.RequestHandler):
	def get(self):
		self.response.out.write("Great! You know the calendar!")

class Rot13Handler(Handler):
	def get(self):
		self.render("rot13.html",text='')

	def post(self):
		word=self.request.get('text')
		word=rot13(word)
		self.render("rot13.html",text=word)

import re
def validCheck(exp,name):
	the_re=re.compile(exp)
	return the_re.match(name)

class SignupHandler(Handler):
	def write_form(self,username='',password='',verify='',email='',invalidName='',invalidPass='',invalidVerify='',invalidEmail=''):
		self.render("signup.html",username=username,password=password,verify=verify,email=email,invalidName=invalidName,invalidPass=invalidPass,invalidVerify=invalidVerify,invalidEmail=invalidEmail)

	def get(self):
		self.write_form()

	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')
		verify=self.request.get('verify')
		email=self.request.get('email')
		userCheck=validCheck(r"^[a-zA-Z0-9_-]{3,20}$",username)
		passCheck=validCheck(r"^.{3,20}$",password)
		emailCheck=validCheck(r"^[\S]+@[\S]+\.[\S]+$",email)
		checkUser=db.GqlQuery("SELECT * FROM User where name= :1",username)
		checkUser=checkUser.get()
		try:
			checkUser=checkUser.name
		except Exception, e:
			checkUser=None

		if(userCheck and passCheck and (not email or emailCheck) and password==verify and not checkUser):
			user=User(name=username,password=make_pw_hash(username,password))
			user.put()
			self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s' % (make_secure_val(username),'/')))
			self.redirect('/welcome')
		else:
			if checkUser:
				usertext='This username is already taken'
			else:
				usertext=''
			passtext=''
			verifytext=''
			emailtext=''
			if(not userCheck):
				usertext='Invalid username'
			if(not passCheck):
				passtext='Invalid password'
			elif(password != verify):
				verifytext="Passwords didn't match"
			if(email and not emailCheck):
				emailtext='Invalid email'

			self.write_form(username,'','',email,usertext,passtext,verifytext,emailtext)

class LoginHandler(Handler):
	def get(self):
		self.render("login.html",invalid="")

	def post(self):
		username=self.request.get('username')
		password=self.request.get('password')
		checkUser=db.GqlQuery("SELECT * FROM User where name= :1",username)
		checkUser=checkUser.get()
		if checkUser and valid_pw(username,password,checkUser.password):
			self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s' % (make_secure_val(username),'/')))
			self.redirect('/welcome')
		else:
			self.render("login.html",invalid="Invalid login")
		
class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie',str('name=%s;path=%s' % ('','/')))
		self.redirect('/signup')
		
def frontpage(update=False):
	global dbTime
	key='front'
	articles=memcache.get(key)
	if update or not articles:
		articles=db.GqlQuery("SELECT * FROM Article ORDER BY created DESC LIMIT 10")
		logging.error("DB HIT")
		memcache.set('fronttime',time.time())
		articles=list(articles)
		memcache.set(key,articles)
	return articles

class BlogHandler(Handler):
	def get(self):
		articles=frontpage()
		self.render("blog.html",articles=articles)
		dbTime=memcache.get('fronttime') or time.time()
		self.response.out.write("Queried %s seconds ago" % (time.time()-dbTime))

class BlogJson(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'application/json'
		articles=frontpage()
		result=[]
		for article in articles:
			result.append({'title':article.title,'subject':article.content,'created':article.created.strftime("%b %d %Y %H:%M:%S")})
		self.response.out.write(json.dumps(result))

class BlogPostHandler(Handler):
	def get(self):
		self.render("newpost.html",title="",content="",error="")

	def post(self):
		title=self.request.get('subject')
		content=self.request.get('content')
		if(title and content):
			a=Article(title=title,content=content)
			a.put()
			frontpage(True)
			self.redirect('/'+str(a.key().id()))
		else:
			self.render("newpost.html",title=title,content=content,error="Both title and content are required!")
	
class GetBlogPostHandler(Handler):
	def get(self):
		theid=self.request.path
		theid=long(theid[1:])
		key=str(theid)
		article=memcache.get(key)
		if article is None:
			article=Article.get_by_id(theid)
			memcache.set(key+'time',time.time())
			memcache.set(key,article)
		if article:
			self.render("article.html",article=article)
			dbEachTime=memcache.get(key+'time') or time.time()
			self.response.out.write("Queried %s seconds ago" %(time.time()-dbEachTime))

class GetBlogPostJson(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'application/json'
		theid=self.request.path
		theid=long(theid[1:-5])
		key=str(theid)
		article=memcache.get(key)
		if article:
			self.response.out.write(json.dumps([{'title':article.title,'subject':article.content,'created':article.created.strftime("%b %d %Y %H:%M:%S")}]))

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		name=self.request.cookies.get('name')
		if(name):
			name=check_secure_val(name)
		if name:
			self.response.out.write("Welcome, "+name+"!")
		else:
			self.redirect("/signup")
class FlushHandler(webapp2.RequestHandler):
	def get(self):
		memcache.flush_all()
		self.redirect('/')

app = webapp2.WSGIApplication([
	('/thanks',ThanksHandler),('/rot13',Rot13Handler),('/signup',SignupHandler),('/login',LoginHandler),('/logout',LogoutHandler),('/welcome',WelcomeHandler),('/',BlogHandler),('/.json',BlogJson),('/newpost',BlogPostHandler),(r'^/[0-9]+$',GetBlogPostHandler),(r'^/[0-9]+\.json$',GetBlogPostJson),('/flush',FlushHandler)], debug=True)