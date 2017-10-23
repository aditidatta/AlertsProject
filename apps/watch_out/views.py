from django.shortcuts import render, redirect
from django.http import HttpRequest
from django.http import JsonResponse
import json
import requests
import datetime
import bcrypt
from django.contrib import messages
import math
from . import models
from .models import Users, Alerts

# Create your views here.





def index(request):

	return render(request, 'watch_out/index.html')

def login(request):

	return render(request, 'watch_out/login.html')

def register(request):

	return render(request, 'watch_out/register.html')

def op(request):

	return render(request, 'watch_out/op.html')

def alert(request):

	return render(request, 'watch_out/alert.html')


def addalert(request):
	print ("inside addalert")
	if "user_id" not in request.session:
		print ("user not logged in")
		return redirect('/login')
	else:
		print ("user logged in")
		return render(request, 'watch_out/addalert.html')

def display(request):

	return render(request, 'watch_out/display.html')


def formprocess(request):

	print('im in the formprocess')
	data = request.POST
	radius = data['radius']
	lat = data['lat']
	lng = data['lng']
	address = data['address']
	payload = {'lat': lat, 'lon': lng, 'radius': radius, 'key': 'privatekeyforspotcrimepublicusers-commercialuse-877.410.1607'}
	r = requests.get('https://api.spotcrime.com/crimes.json', params=payload)
	#print type(r.json())
	print r.json()['crimes'][0]
	#print (address)
	data = retreivealert(lat, lng, radius) #calling it from here
	print data
	final = {u'crimes' : {u'spotcrime' : r.json()['crimes'], u'user' : data}}
	print ('im about to return stuff')
	return JsonResponse(final)

# incomplete method
def retreivealert(lat, lng, desired_dist):
	alerts = models.Alerts.objects.all()
	data = []
	lat1 = math.radians(float(lat))
	print float(lat)
	lng1 = math.radians(float(lng))
	print lng1
	for x in alerts:
		alert = x.__dict__
		if alert['lati']:
			lat2 = math.radians(float(alert['lati']))
			print lat2
			lng2 = math.radians(float(alert['longi']))
			print lng2
			dist = math.acos(math.sin(lat1)*math.sin(lat2) + math.cos(lat1)*math.cos(lat2)*math.cos(lng2-lng1)) * 3981

			if dist < desired_dist*100:
				data.append({u'type':alert['crime'], u'date':alert['date'].date().strftime("%m/%d/%y %H:%M %p"), u'address':alert['address'], u'link':alert['description'], u'lat' : float(alert['lati']), u'lon': float(alert['longi'])})

	return data




def addalertprocess(request):
	#inputs = request.POST
	print 'i am in add alert now'
	addr = request.POST['address']
	lat = request.POST['lat']
	lng = request.POST['lng']
	print addr
	print round(float(str(lat)), 6)
	print round(float(str(lng)), 6)
	thisuser = models.Users.objects.get(id = request.session['user_id'])
	alert= models.Alerts.objects.create(address = addr, lati=round(float(str(lat)), 6), longi=round(float(str(lng)), 6), date= request.POST.get('date'), crime= request.POST.get('type'), description=request.POST.get('description'), poster=thisuser)
	return redirect('/')



#LOGIN REGS
def loginprocess(request):
	post = request.POST
	print post

	email=request.POST.get('email')
	print "email", email
	password=request.POST.get('password')

	#check if existing user or input error
	existuser = models.Users.objects.loginvalid(request,email, password)
	if existuser == True:
		print "user exist"
		user_id = models.Users.objects.get(email = email).id
		request.session['user_id'] = user_id
		context = {
			'username' : email,
			'status' : "logged in"
		}
		return redirect('/')
	##DISPLAY MSGED TO SHOW ERROR
	for ind in range (0, len(existuser)):
		messages.error(request, existuser[ind])
	return redirect('/registration')

def registerprocess(request):
	#GET USER INPUT

	name=request.POST.get('name')
	email = request.POST.get('email')
	password=request.POST.get('password')
	repassword=request.POST.get('re_password')
	newuser = models.Users.objects.registervalid(name, email, password, repassword)
	print newuser
	if not newuser:
		hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
		newuser = models.Users.objects.create(name=name, email=email, hashed_pw=hashed)
		user_id = models.Users.objects.get(email = email).id
		request.session['user_id'] = user_id
		return redirect('/')
	if newuser[0] == "User already exist! Please login instead!":
		print("go to login page")
		return redirect('/login')

	for ind in range (0, len(newuser)):
		messages.error(request, newuser[ind])
	return redirect('/registration')


def loggingout(request):
	request.session.pop('user_id')
	return redirect('/')
