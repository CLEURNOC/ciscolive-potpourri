#!/usr/bin/python
#
# Copyright (c) 2017-2018  Joe Clarke <jclarke@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from pyad import *
import sys
import re
from functools import wraps
from flask import request, Response, session
from flask import Flask
import pythoncom
import CLEUCreds


AD_DN_BASE = 'cn=Users, dc=ad, dc=ciscolive, dc=network'
AD_DOMAIN = 'ad.ciscolive.network'
AD_DC = 'dc1-ad.ad.ciscolive.network'

app = Flask('CLEU Password Reset')


def query_user(username, password, target_user):
    global AD_DC, AD_DN_BASE

    try:
        adcontainer.ADContainer.from_dn(AD_DN_BASE, options={
                                        'ldap_server': AD_DC, 'username': username, 'password': password})
    except Exception as e:
        print(e)
        return None

    try:
        q = adquery.ADQuery(
            options={'ldap_server': AD_DC, 'username': username, 'password': password})
        q.execute_query(attributes=['distinguishedName'], where_clause="sAMAccountName='{}'".format(
            target_user), base_dn=AD_DN_BASE, options={'ldap_server': AD_DC, 'username': username, 'password': password})
        for row in q.get_results():
            return row['distinguishedName']
    except Exception as e:
        print(e)
        return None


def check_auth(username, password):
    global AD_DOMAIN

    pythoncom.CoInitialize()
    if 'dn' in session:
        return True

    if not re.search(r'@{}$'.format(AD_DOMAIN), username):
        username += '@{}'.format(AD_DOMAIN)

    target_username = username.replace('@{}'.format(AD_DOMAIN), '')

    try:
        dn = query_user(username, password, target_username)
        if dn is not None:
            session['dn'] = dn
            return True
        else:
            try:
                dn = None
                dn = query_user(CLEUCreds.AD_ADMIN,
                                CLEUCreds.AD_PASSWORD, target_username)
                if dn is None:
                    return False

                adu = aduser.ADUser.from_dn(dn, options={
                                            'ldap_server': AD_DC, 'username': CLEUCreds.AD_ADMIN, 'password': CLEUCreds.AD_PASSWORD})
                obj = adu.get_attribute('pwdLastSet', False)
                if password == CLEUCreds.DEFAULT_USER_PASSWORD and int(obj.highpart) == 0 and int(obj.lowpart) == 0:
                    session['dn'] = dn
                    return True

            except Exception as ie:
                print(ie)
                return False
    except Exception as e:
        print(e)
        return False

    return False


def authenticate():
    return Response(
        'Failed to verify credentials for password reset.\n'
        'You have to login with proper credentials.', 401,
        {'WWW-Authenticate': 'Basic realm="CLEU Password Reset"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/reset-password', methods=['POST'])
@requires_auth
def reset_password():
    new_pw = request.form.get('new_pass')
    new_pw_confirm = request.form.get('new_pass_confirm')
    if new_pw.strip() == '' or new_pw_confirm.strip() == '':
        return Response('''
<html>
  <head>
    <title>Bad Password</title>
  </head>
  <body>
  <p>You must specify a new password.</p>
  </body>
</html>''', mimetype='text/html')

    if new_pw != new_pw_confirm:
        return Response('''
<html>
  <head>
    <title>Bad Password</title>
  </head>
  <body>
    <p>Passwords did not match</p>
  </body>
</html>''', mimetype='text/html')

    adu = aduser.ADUser.from_dn(session['dn'], options={
                                'ldap_server': AD_DC, 'username': CLEUCreds.AD_ADMIN, 'password': CLEUCreds.AD_PASSWORD})
    try:
        adu.set_password(new_pw)
    except Exception as e:
        return Response('''
<html>
  <head>
    <title>Failed to Reset Password</title>
  </head>
  <body>
  <h1>Password Reset Failed!</h1>
  <p>{}</p>
  </body>
</html>'''.format(e), mimetype='text/html')

    adu.grant_password_lease()
    del session['dn']

    return Response('''
<html>
  <head>
    <title>Password Changed Successfully!</title>
  </head>
  <body>
    <h1>Password Changed Successfully!</h1>
  </body>
</html>''', mimetype='text/html')


@app.route('/')
@requires_auth
def get_main():
    page = '''
<html>
  <head>
    <title>Password Reset Form</title>
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
      <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">      <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/datatables/1.10.12/css/dataTables.bootstrap.min.css" integrity="sha256-7MXHrlaY+rYR1p4jeLI23tgiUamQVym2FWmiUjksFDc=" crossorigin="anonymous" />

      <meta name="viewport" content="width=device-width, initial-scale=1">
      <script type="text/javascript" src="//cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js" integrity="sha256-ZosEbRLbNQzLpnKIkEdrPv7lOy9C27hHQ+Xp8a4MxAQ=" crossorigin="anonymous"></script>
  		<script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>      <script type="text/javascript" src="//cdnjs.cloudflare.com/ajax/libs/datatables/1.10.12/js/jquery.dataTables.min.js" integrity="sha256-TX6POJQ2u5/aJmHTJ/XUL5vWCbuOw0AQdgUEzk4vYMc=" crossorigin="anonymous"></script>
<script type="text/javascript" src="//cdnjs.cloudflare.com/ajax/libs/datatables/1.10.12/js/dataTables.bootstrap.min.js" integrity="sha256-90YqnHom4j8OhcEQgyUI2IhmGYTBO54Adcf3YDZU9xM=" crossorigin="anonymous"></script>
    <script>
    function verify() {
	if (!$('#new_pass').val().trim()) {
		alert('Please specify a new password.');
		return false;
	}
    if (!$('#new_pass_confirm').val().trim()) {
        alert('Please confirm the new password.');
        return false;
    }
    if ($('#new_pass_confirm').val().trim() != $('#new_pass').val().trim()) {
        alert('Passwords do not match.');
        return false;
    }
	return true;
	}
    </script>
    </head>
    <body>
    <div class="container" role="main" style="width: 100%;">
      <div class="page-header">
        <h3>Password Reset Form</h3>
      </div>

      <div class="row">
        <div class="col-sm-8">

          <form method="POST" onSubmit="return verify();" action="/reset-password">
            <div class="form-group">
              <label for="new_pass">New Password:</label>
              <input type="password" name="new_pass" id="new_pass" class="form-control" placeholder="New Password">
           </div>
           <div class="form-group">
             <label for="new_pass_confirm">Confirm New Password:</label>
             <input type="password" name="new_pass_confirm" id="new_pass_confirm" class="form-control" placeholder="Confirm New Password">
           </div>
           <div class="form-group">
             <input type="submit" name="submit" value="Reset My Password!" class="btn btn-primary">
             <input type="reset" name="reset" value="Start Over" class="btn btn-default">
           </div>
         </form>
       </div>
     </div>
     </div>
  </body>
</html>'''

    return Response(page, mimetype='text/html')

if __name__ == '__main__':
    app.secret_key = CLEUCreds.AD_PASSWORD
    app.run(host='10.100.253.25', port=8443,
            threaded=True, ssl_context=('chain.pem', 'privkey.pem'))
