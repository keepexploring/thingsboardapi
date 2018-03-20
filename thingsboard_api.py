import hug
import jwt
import json
import psycopg2
import time
from falcon import HTTPUnauthorized
from datetime import datetime, timedelta
import yaml
import pdb

# to run in production:
# gunicorn -w 4 -b 127.0.0.1:5000 thingsboard_api:__hug_wsgi__

# to run for testing:
# hug -f thingsboard_api.py
#config = configparser.ConfigParser()
#config.read('init.ini')

params = yaml.load(open('init.yaml', 'r') )

JWT_OPTIONS = params['AUTH']['JWT_OPTIONS']
SECRET_KEY = params['AUTH']['SECRET_KEY']
JWT_ISSUER = params['AUTH']['JWT_ISSUER']
JWT_AUDIENCE = params['AUTH']['JWT_AUDIENCE']
JWT_OPTIONS_ALGORITHM = params['AUTH']['JWT_OPTIONS_ALGORITHM']


try:
    conn = psycopg2.connect("dbname='thingsboard' user='thingsboard@thingsboard' host='thingsboard.postgres.database.azure.com' password='gsHExnKT7MrejZE3nF3ZKnJhNFA9'")
except:
    print("I am unable to connect to the database")


def jwt_token_verify(auth_header):
    """
    Verifier function for hug token authenticator
    :param auth_header:
    :return:
    """
    # Hug do not extract Bearer prefix
    auth_token, payload = parse_header(auth_header)
    return payload

def parse_header(authorization_header, exception_class=HTTPUnauthorized):
    """
    Parses an authorization header. Accepts a custom Exception if any failure
    :param authorization_header:
    :param exception_class:
    :return:
    """
    if authorization_header:
        parts = authorization_header.split()

        if parts[0].lower() != 'bearer' or len(parts) == 1 or len(
                parts) > 2:
            raise exception_class("invalid_header")

        jwt_token = parts[1]
        try:
            # Decode token
            payload = decode_token(jwt_token)
            return jwt_token, payload
        except jwt.ExpiredSignature:  # pragma: no cover
            raise exception_class("token is expired")

        except jwt.InvalidAudienceError:  # pragma: no cover
            raise exception_class("incorrect audience")

        except jwt.DecodeError:  # pragma: no cover
            raise exception_class("token signature is invalid")

        except jwt.InvalidIssuerError:  # pragma: no cover
            raise exception_class("token issuer is invalid")

        except Exception as exc:  # pragma: no cover
            raise exception_class(exc)
    else:  # pragma: no cover
        raise exception_class("Authorization header not present")

token_key_authentication = hug.authentication.token(jwt_token_verify)

@hug.get('/get_customers', requires=token_key_authentication)
def get_customers(hug_user):
    #pdb.set_trace()
    cur = conn.cursor()
    query = "SELECT * from customer;"
    try:
        cur.execute(query)
        rows = cur.fetchall()
        data_list = []
        for row in rows:
            data_list.append({"customer_id":row[0], "additional_info":row[1], "address":row[2], "address2":row[3], "city":row[4], "country":row[5],"email":row[6],"phone":row[7],"search_text":row[8],"state":row[9],"tenant_id":row[10],"title":row[11],"zip":row[12] })
        return {"data":data_list}
    except:
        print("error")
        return {"error":"query failed"}

@hug.post('/get_devices', requires=token_key_authentication)
def get_devices(hug_user, customer_id):
    #pdb.set_trace()
    cur = conn.cursor()
    query = "SELECT * from device WHERE customer_id = " + "'"+str(customer_id)+"'" + ";"
    data = {}
    try:
        cur.execute(query)
        rows = cur.fetchall()
        data_list = []
        for row in rows:
            data_list.append({"device_id":row[0], "additional_info":row[1], "customer_id":row[2], "type":row[3], "name":row[4], "tenant_id":row[5] })
        data['data'] = data_list
    except:
        print("error")
        data['error'] = "query failed"

    return data
    

@hug.post('/get_data', requires=token_key_authentication)
def get_data(hug_user,device_id, startT, endT,keys=['PR']):
    #pdb.set_trace()
    cur = conn.cursor()
    data = {}
    if 'PR' in keys:
        query_PR = "SELECT entity_id, ts, key, dbl_v from ts_kv WHERE entity_id = " + "'" + str(device_id) + "'" + " AND key = 'PR' AND ts >= " + str(int(startT)) +" AND ts < " + str(int(endT))+";"
        try:
            cur.execute(query_PR)
            rows_PR = cur.fetchall()
            data_list = []
            for row in rows_PR:
                data_list.append({"entity_id":row[0], "ts":row[1], "key":row[2], "value":row[3] })
            data['PR'] = data_list
        except:
            print("error")
    else:
        rows_PR = None

    if 'SD' in keys:
        query_SD = "SELECT entity_id, ts, key, dbl_v from ts_kv WHERE entity_id = " + "'" + str(device_id) + "'" + " AND key = 'SD' AND ts >= " + str(int(startT)) +" AND ts < " + str(int(endT))+";"
        try:
            cur.execute(query_SD)
            rows_SD = cur.fetchall()
            data_list = []
            for row in rows_SD:
                data_list.append({"entity_id":row[0], "ts":row[1], "key":row[2], "value":row[3] })
            data['SD'] = data_list
        except:
            print("error")
    else:
        rows_SD = None

    if 'RSSI' in keys:
        query_RSSI = "SELECT entity_id, ts, key, long_v from ts_kv WHERE entity_id = " + "'" + str(device_id) + "'" + " AND key = 'RSSI' AND ts >= " + str(int(startT)) +" AND ts < " + str(int(endT))+";"
        try:
            cur.execute(query_RSSI)
            rows_RSSI = cur.fetchall()
            data_list = []
            for row in rows_RSSI:
                data_list.append({"entity_id":row[0], "ts":row[1], "key":row[2], "value":row[3] })
            data['RSSI'] = data_list
        except:
            print("error")
    else:
        rows_RSSI = None

    try:
        cur.execute(query_PR)
    except:
        print("error")
    rows = cur.fetchall()
    #data_list=[]
    

    return data
    #return { "PR":rows_PR,"SD":rows_SD,"RSSI":rows_RSSI } # just return like this to save doing more computations - do this on the other end


def decode_token(token, options=JWT_OPTIONS):
    """
    Decodes a JWT token and returns payload info
    :return:
    """
    return jwt.decode(
        token,
        SECRET_KEY,
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options=options,
        algorithms=(JWT_OPTIONS_ALGORITHM,)
    )


@hug.get('/token_authenticated', requires=token_key_authentication)
def token_auth_call(user: hug.directives.user):
    return 'You are user: {0} with data {1}. Time was {2}'.format(user['user'], user['role'], user['time'])


@hug.post('/token_generation') 
def token_gen_call(username, password, exp=None):
    """Authenticate and return a token"""
    #pdb.set_trace()
    
    username_set = params['AUTH']['username_set']
    password_set = params['AUTH']['password_set']

    """
    Creates JWT Token
    :return:
    """
    if exp is None:
        exp = datetime.utcnow() + timedelta(seconds=3600)
    _token = {
        'aud': JWT_AUDIENCE,
        'exp': exp,
        'iss': JWT_ISSUER,
        'user': username,
        'role': 'admin',
        'time':time.time()
    }
    _token.update(_token)
    
    if password_set == password and username_set == username: # example, don't do this in production
        return {"token" : jwt.encode(_token, SECRET_KEY, algorithm=JWT_OPTIONS_ALGORITHM).decode('utf-8') }
    return 'Invalid username and/or password for user: {0}'.format(username)

