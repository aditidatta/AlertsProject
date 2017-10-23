from __future__ import unicode_literals

from django.db import models
import re, bcrypt

# Create your models here.

#class ALertManager(models.Manager):
#####ADD ALERT


class UserManager(models.Manager):
	def loginvalid(self, request, email, password):
		print "login valid!"
		print email
		print password
		error = []

		if email:
			user = Users.objects.filter(email=email)
			if user:
				user = Users.objects.get(email = email)
				if bcrypt.hashpw(password.encode('utf-8'), user.hashed_pw.encode('utf-8')) == user.hashed_pw:
					return True
				else:
					error.append("Password incorrect")
			else:
				error.append("User does not exist")
		else:
			error.append("Please enter an email")
		return error


	def registervalid(self, name, email, password, repass):
		print "register valid!"
		error = []

		#Check all field is filled
		if name and email and password and repass:
			print "good job everything is filled in"

			if Users.objects.filter(email=email):
				error.append("User already exist! Please login instead!")
				return error

			if re.search(r'^[a-zA-Z]+$', name) == False or len(name)<2:
				error.append("Name invalid! Must be at least 8 characters long and consist of only letters")

			if Users.objects.filter(email=email):
				error.append("User already exist! Please login instead!")
				return error

			if re.search(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$', email) == None:
				error.append("Email invalid")

			if len(password) < 8:
				error.append("Password must be longer than 8 character!")

			if repass != password:
				error.append("Password entries do not match")

		else:
			print "dude fill it in"
			error.append("Please fill in all the blanks")

		return error



class Users(models.Model):
	name=models.CharField(max_length=45)
	email=models.CharField(max_length=45)
	hashed_pw= models.CharField(max_length=150)
	created_at=models.DateTimeField(auto_now_add=True)
	objects = UserManager()




class Alerts(models.Model):
	crime=models.CharField(max_length=45)
	date=models.DateTimeField()
	address=models.CharField(max_length=45)
	lati=models.CharField(max_length=15)
	longi=models.CharField(max_length=15)
	description=models.TextField(max_length=500, null=True)
	poster=models.ForeignKey('Users')
