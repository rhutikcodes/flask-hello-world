from flask import Flask,request
import re
import socket
import smtplib
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
app = Flask(__name__)

@app.route('/',methods = ['POST'])
def home():
    payload = request.json
    first_name =payload.get('firstName')
    last_name = payload.get('lastName')
    domain = payload.get('domain')

    return find_emails({
        "firstName": first_name,
        "lastName": last_name,
        "domain": domain,
    })

@app.route('/about')
def about():
    return 'About'


name_regex = re.compile(r'([a-zA-Z])')
domain_regex = re.compile(
  r'''(
[a-zA-Z0-9.-]+         # second-level domain
(\.[a-zA-Z]{2,})       # top-level domain
)''', re.VERBOSE)

#hello
def formats(first, last, domain):
  """
    Create a list of 20 possible email formats combining:
    - First name:          [empty] | Full | Initial |
    - Delimitator:         [empty] |   .  |    _    |    -
    - Last name:           [empty] | Full | Initial |
    """
  list = []

  list.append(first[0] + '@' + domain)  # f@example.com
  list.append(first[0] + last + '@' + domain)  # flast@example.com
  list.append(first[0] + '.' + last + '@' + domain)  # f.last@example.com
  list.append(first[0] + '_' + last + '@' + domain)  # f_last@example.com
  list.append(first[0] + '-' + last + '@' + domain)  # f-last@example.com
  list.append(first + '@' + domain)  # first@example.com
  list.append(first + last + '@' + domain)  # firstlast@example.com
  list.append(first + '.' + last + '@' + domain)  # first.last@example.com
  list.append(first + '_' + last + '@' + domain)  # first_last@example.com
  list.append(first + '-' + last + '@' + domain)  # first-last@example.com
  list.append(first[0] + last[0] + '@' + domain)  # fl@example.com
  list.append(first[0] + '.' + last[0] + '@' + domain)  # f.l@example.com
  list.append(first[0] + '-' + last[0] + '@' + domain)  # f_l@example.com
  list.append(first[0] + '-' + last[0] + '@' + domain)  # f-l@example.com
  list.append(first + last[0] + '@' + domain)  # fistl@example.com
  list.append(first + '.' + last[0] + '@' + domain)  # first.l@example.com
  list.append(first + '_' + last[0] + '@' + domain)  # fist_l@example.com
  list.append(first + '-' + last[0] + '@' + domain)  # fist-l@example.com
  list.append(last + '@' + domain)  # last@example.com
  list.append(last[0] + '@' + domain)  # l@example.com

  return (list)


def verify(email, domain):
  """
    Verify if an email address is valid.
    """
  try:
    print("verifying",email)
    records = dns.resolver.query(domain, 'MX')
  except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
    print('DNS query could not be performed.')
    return None

  # Get MX record for the domain
  mx_record = records[0].exchange
  mx = str(mx_record)

  # Get local server hostname
  local_host = socket.gethostname()

  # Connect to SMTP
  smtp_server = smtplib.SMTP()
  smtp_server.connect(mx)
  smtp_server.helo(local_host)

  smtp_server.mail(email)
  code, message = smtp_server.rcpt(email)

  try:
    smtp_server.quit()
  except smtplib.SMTPServerDisconnected:
    print('Server disconnected. Verification could not be performed.')

  # Return email if SMTP response is positive
  if code == 250:
    print("valid email",email)
    return email
  else:
    print("invalid email",email)
    return None


def verify_emails(emails_list, domain):
  """
    Create a list of all valid addresses out of a list of emails.
    """
  valid = []
  with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(verify, email, domain) for email in emails_list}
    for future in as_completed(futures):
      email = future.result()
      if email is not None:
        valid.append(email)

  return valid


def return_valid(valid, possible):
  """
    Return final output comparing list of valid addresses to the possible ones:
    1. No valid  > Return message
    2. One valid > Copy to clipboard
    3. All valid > Catch-all server
    4. Multiple  > List addresses
    """
  if len(valid) == 0:
    print('No valid email address found')
  elif len(valid) == 1:
    print('Valid email address' + valid[0])
    return valid[0]
  elif len(valid) == len(possible):
    print('Catch-all server. Verification not possible.')
  else:
    print('Multiple valid email addresses found:')
    return valid


def find_emails(payload):
    first_name = payload.get('firstName')
    last_name = payload.get('lastName')
    domain = payload.get('domain')
    emails_list = formats(first_name, last_name, domain)
    print(emails_list,"emails_list")
    valid_list = verify(emails_list, domain)
    print(valid_list,"valid_list")
    final_emails = return_valid(valid_list, emails_list)
    print(final_emails,"final_emails")
    return final_emails
