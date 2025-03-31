import google.oauth2.credentials
import google_auth_oauthlib.flow
import flask, requests
from flask import jsonify, request, make_response, Blueprint
import datetime
import time
# from datetime import datetime
import pytz
import psycopg2
import os
import json
import redis
from common import logger
from auth.secretManager import access_secret_version
import jwt
from dotenv import load_dotenv

def load_environment_variables(env_file):
    """환경 변수 파일을 로드합니다."""
    load_dotenv(dotenv_path=env_file)

def get_environment_variable(key):
    """환경 변수 값을 가져옵니다."""
    return os.getenv(key)

# 환경 변수 로드 (빌드 시 환경에 따라 파일 선택)
if os.environ.get('ENV') == 'prd':
    load_environment_variables('.env.prd')
else:
    load_environment_variables('.env.dev')

REDIRECT_URL = get_environment_variable('REDIRECT_URL')
CLIENT_SECRET = access_secret_version()

oauth2Authorization = Blueprint('oauth2Authorization', __name__, url_prefix='/api/oauth2')

SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly',
          'https://www.googleapis.com/auth/calendar.readonly',
          'openid', 
          'https://www.googleapis.com/auth/userinfo.email']

@oauth2Authorization.route('/', methods=['GET']) # Blueprint에서 url_prefix를 설정했기 때문에 /api/oauth2 생략 가능
def authorize(): 
    logger.LoggerFactory._LOGGER.info("authorize")

    try:
        # Required, call the from_client_secrets_file method to retrieve the client ID from a
        # client_secret.json file. The client ID (from that file) and access scopes are required. (You can
        # also use the from_client_config method, which passes the client configuration as it originally
        # appeared in a client secrets file but doesn't access the file itself.)
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)

        # Required, indicate where the API server will redirect the user after the user completes
        # the authorization flow. The redirect URI is required. The value must exactly
        # match one of the authorized redirect URIs for the OAuth 2.0 client, which you
        # configured in the API Console. If this value doesn't match an authorized URI,
        # you will get a 'redirect_uri_mismatch' error.
        flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
        # flow.redirect_uri = flask.url_for('http://localhost:8000/api/oauth2/code', _external=True)

        # Generate URL for request to Google's OAuth 2.0 server.
        # Use kwargs to set optional request parameters.
        authorization_url, state = flow.authorization_url(
            # Recommended, enable offline access so that you can refresh an access token without
            # re-prompting the user for permission. Recommended for web server apps.
            access_type='offline',
            # Optional, enable incremental authorization. Recommended as a best practice.
            include_granted_scopes='true',
            # Optional, if your application knows which user is trying to authenticate, it can use thisxw
            # parameter to provide a hint to the Google Authentication Server.
            login_hint='hint@example.com',
            # Optional, set prompt to 'consent' will prompt the user for consent
            prompt='consent')

        # print("flask.session['state'] : ", flask.session)
        print("flow : ", flow)
        flask.session['state'] = state
        print("authorization_url : ", authorization_url)

        # return flask.redirect(authorization_url)
        return jsonify({'authorizationUrl': authorization_url})
    
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : ", e)

        return ("시스텥 관리자에게 연락하세요.")


def checkAuthorization(tokenSaveType):
    # print("checkAuthorization")
    logger.LoggerFactory._LOGGER.info("checkAuthorization")

    if tokenSaveType == 'S':
        print("Session에 저장된 토큰을 확인합니다.")

        if 'credentials' not in flask.session: 
            logger.LoggerFactory._LOGGER.info("Session 내 token이 없습니다.") 
            return 'F'
    
        else:
            print("Session 내 token이 있습니다. 만료 여부를 확인합니다.")
            print("flask.session['credentials']['expiry'] : ", flask.session['credentials']['expiry'])
            # Expired = checkIsTokenExpired_Session(flask.session['credentials']['expiry'])
            Expired = checkIsTokenExpired(tokenSaveType, flask.session['credentials']['expiry'])
            
            if Expired:
                print("Session 내 token이 존재하지만 만료되었습니다.")
                result = getTokenRefreshed('S')
                print(result)
                # return False
                # return True
                return 'R'
            else:
                print("Session 내 token이 존재합니다.")
                # return False
                return 'E'
        
    elif tokenSaveType == 'C':
        logger.LoggerFactory._LOGGER.info("Cookie에 저장된 토큰을 확인합니다.") 
        # result = checkAuthorization_Cookies()
        # print("result : ", result)
        # return result

    elif tokenSaveType == 'R':
        logger.LoggerFactory._LOGGER.info("Redis에 저장된 토큰을 확인합니다.") 
        # logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : {}".format(flask.session['credentials'])) 
        # logger.LoggerFactory._LOGGER.info("flask.session : {}".format(flask.session)) 
        # logger.LoggerFactory._LOGGER.info("'credentials' not in flask.session : {}".format('credentials' not in flask.session)) 

        cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.
        # logger.LoggerFactory._LOGGER.info("cookies : {}".format(cookies)) 
        logger.LoggerFactory._LOGGER.info("cookies.get('email') : {}".format(cookies.get("email"))) 
        # logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : {}".format(flask.session['credentials'])) 
        logger.LoggerFactory._LOGGER.info("flask.session : {}".format(flask.session)) 

        # if not cookies.get("email"):
        #     logger.LoggerFactory._LOGGER.info("쿠키가 없습니다.")
        #     authorize()
        #     return 'F'
        
        # else:
        #     expiration_time_str = cookies.get("expiry")

        if 'credentials' not in flask.session: 
            logger.LoggerFactory._LOGGER.info("사용자 이메일 주소가 Session에 없습니다.") 
            return 'F'
        else:
            logger.LoggerFactory._LOGGER.info("사용자 이메일 주소가 Session에서 확인됐습니다. : {}".format(flask.session['credentials']['email'])) 
            r = redis.Redis(host='localhost', port=6379, db=0)
            logger.LoggerFactory._LOGGER.info("flask.session['credentials']['email'] : {}".format(flask.session['credentials']['email'])) 
            email = flask.session['credentials']['email']
            key = f"user:{email}:access_token"
            token_data = r.get(key)
            logger.LoggerFactory._LOGGER.info("token_data : {}".format(token_data)) 

            if token_data:
                logger.LoggerFactory._LOGGER.info("json.loads(token_data)['value'] : {}".format(json.loads(token_data)['value'])) 
                # return json.loads(token_data)['value']
                return 'E'

            # return None
            return 'F'
            # {
            #     "result":True,
            #     "resultCode":200,
            #     "data":{
            #         "user":"danniel.kil@gmail.com",
            #         "token":"abcd1234"
            #     },
            #     "message":"데이터 조회에 성공했습니다."
            # }
        
    else:
        print("저장 타입을 지정하지 않았습니다.")
        return False
    
        

def checkIsTokenExpired(tokenSaveType, expiration_time_str):
    print("checkIsTokenExpired tokenSaveType : ", tokenSaveType)
    logger.LoggerFactory._LOGGER.info("checkAuthorization")
    """ 액세스 토큰 만료 시간이 있고 만료되었는지 확인합니다."""

    if tokenSaveType == 'S':
        print("tokenSaveType is Session")

        try:
            kst = pytz.timezone('Asia/Seoul')
            # expiry_kst = expiration_time_str.astimezone(kst)
            expiry_kst = expiration_time_str
            # print("expiry_kst : ", expiry_kst)

            # 현재 KST 시간
            now_kst = datetime.datetime.now(kst)
            now_kst = now_kst + datetime.timedelta(hours=9)
            # now_kst = now_kst + datetime.timedelta(seconds=35990) # test
            # print("now_kst : ", now_kst)

            # 만료 시간과 현재 시간의 차이 계산 (초 단위)
            time_difference = (expiry_kst - now_kst).total_seconds()
            # print("time_difference : ", time_difference)
            logger.LoggerFactory._LOGGER.info("time_difference : {}".format(time_difference))

            # 만료 시간이 60초 이하인 경우 체크
            if time_difference <= 60:
                # print("토큰 만료가 60초 이하로 남았습니다.")
                logger.LoggerFactory._LOGGER.info("토큰 만료가 60초 이하로 남았습니다.")
                return True
            else:
                # print(f"토큰 만료까지 {time_difference:.0f}초 남아 아직 유효합니다.")
                logger.LoggerFactory._LOGGER.info(f"토큰 만료까지 {time_difference:.0f}초 남아 아직 유효합니다.")
                return False

        except ValueError:
            # print("잘못된 시간 형식입니다.")
            logger.LoggerFactory._LOGGER.info("잘못된 시간 형식입니다.")
            # return False
            return True
        
    elif tokenSaveType == 'C':
        # print("tokenSaveType is Cookie")
        logger.LoggerFactory._LOGGER.info("tokenSaveType is Cookie")

    elif tokenSaveType == 'R':
        # print("tokenSaveType is Redis")
        logger.LoggerFactory._LOGGER.info("tokenSaveType is Redis")

    else:
        # print("tokenSaveType이 잘못됐습니다.")
        logger.LoggerFactory._LOGGER.error("tokenSaveType이 잘못됐습니다.")

    
def checkAuthorization_Cookies():
    # print("checkAuthorization_Cookies")
    logger.LoggerFactory._LOGGER.info("tokenSaveType is Redis")

    """
    클라이언트의 쿠키 값을 모두 읽어와 출력합니다.
    1) 쿠키가 아예 없는 경우
    2) 특정 쿠키명을 확인하는 경우를 추가했습니다.
    """
    cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.

    # if not cookies:
    if not cookies.get("token"):
        # print("쿠키가 없습니다.")
        logger.LoggerFactory._LOGGER.info("쿠키가 없습니다.")
        authorize()
        # return False
        return 'F'
    
    else:
        # 특정 쿠키명 확인
        # specific_cookie_name = "token"  # 확인하려는 쿠키 이름
        # specific_cookie_value = cookies.get(specific_cookie_name)
        expiration_time_str = cookies.get("expiry")

        Expired = checkIsTokenExpired(expiration_time_str)
        # print("Expired : ", Expired)

        if Expired:
            # print("쿠키(token) 값이 존재하지만 만료되었습니다.")
            logger.LoggerFactory._LOGGER.info("쿠키(token) 값이 존재하지만 만료되었습니다.")
            result = getTokenRefreshed()
            print(result)
            # return False
            return True
            # return 'R'
        else:
            # print("쿠키(token) 값이 존재합니다.")
            logger.LoggerFactory._LOGGER.info("쿠키(token) 값이 존재합니다.")
            # return False
            return 'E'



# @oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback():
    # print("oauth2callback")
    logger.LoggerFactory._LOGGER.info("oauth2callback")

    code = request.args.get('code')


    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)
    

    flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
    # flow.redirect_uri = 'http://localhost:8000/api/hello'

    authorization_response = flask.request.url
    # print("flask.request.url : ", flask.request.url)
    # print("flask.request : ", flask.request)
    flow.fetch_token(authorization_response=authorization_response)
    # flow.fetch_token(authorization_response=authorization_response, verify=False)

    # Store the credentials in the session.
    # ACTION ITEM for developers:
    #     Store user's access and refresh tokens in your data store if
    #     incorporating this code into your real app.
    credentials = flow.credentials
    logger.LoggerFactory._LOGGER.info("credentials : ", credentials)

    flask.session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'expiry': credentials.expiry,
        # 'expiry': remaining_seconds_kst,
        'id_token': credentials.id_token,
        'granted_scopes': credentials.granted_scopes}
    
    # save_user_credentials(user_id, access_token, refresh_token, expiry, id_token_info)
    # save_user_credentials(user_id, credentials.token, credentials.refresh_token, credentials.expiry, id_token_info)

    # print("flask.session['credentials'] : ", flask.session['credentials'])
    # print("credentials : ", credentials)

    # if code:
    #     return jsonify({"code": code})
    # else:
    #     return jsonify({"error": "Code parameter is missing"}), 400
    # print("request.url : ", request.url)
    return flask.redirect('/api/data')
    # return flask.redirect('http://localhost:3000/test')
    # return jsonify({"login": True, "data": ""})


# @oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback_Cookie():
    # print("oauth2callback_Cookie")
    logger.LoggerFactory._LOGGER.info("oauth2callback_Cookie")


    # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)


    flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
    
    authorization_response = flask.request.url
    
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    # print(credentials.__dict__) # flow.credentials 내부 상세 속성 확인(중요)

    # 문자열을 datetime 객체로 변환
    # expiration_time = datetime.datetime.fromisoformat(expiration_time_str)
    # expiration_time = expiration_time + datetime.timedelta(hours=9)
    expiration_time = credentials.expiry + datetime.timedelta(hours=9)

    data = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'expiry': expiration_time,
        'id_token': credentials.id_token,
        'granted_scopes': credentials.granted_scopes
    }
    
    # data = request.get_json()  # JSON 데이터 파싱
    # data = data.get_json()  # JSON 데이터 파싱
    # print("data : ", data["token"])

    # response = make_response("쿠키 설정 완료!")
    response = make_response(flask.redirect('/api/data'))

    for key, value in data.items():
        print("{}:{}".format(key, value))
        response.set_cookie(key, str(value))  # 쿠키 설정

    flask.session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'expiry': credentials.expiry,
        'granted_scopes': credentials.granted_scopes}
    
    logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : ", flask.session['credentials'])
    
    # return flask.redirect('/api/data')
    return response


# @oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback_Session():
    # print("oauth2callback_Session")
    logger.LoggerFactory._LOGGER.info("oauth2callback_Session")

    try:
        # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)
        
        flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
        
        authorization_response = flask.request.url
        # print("flask.request.url", flask.request.url)
        
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        # 문자열을 datetime 객체로 변환
        expiration_time = credentials.expiry + datetime.timedelta(hours=9)

        if credentials.id_token:
            try:
                # id_token 디코딩
                decoded_token = jwt.decode(credentials.id_token, options={"verify_signature": False})

                # 사용자 정보 추출
                email = decoded_token.get('email')
                print(f"사용자 이메일: {email}")

            except jwt.ExpiredSignatureError:
                print("id_token이 만료되었습니다.")
            except jwt.InvalidTokenError:
                print("유효하지 않은 id_token입니다.")
            except Exception as e:
                print(f"id_token 디코딩 오류: {e}")
        else:
            print("id_token이 없습니다.")

        flask.session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            # 'expiry': credentials.expiry,
            'expiry': expiration_time,
            'id_token': credentials.id_token,
            'email': email,
            'granted_scopes': credentials.granted_scopes}
        
        # r = redis.Redis(host='localhost', port=6379, db=0)
        # expiration = 60  # 1분
        # key = f"user:{email}:access_token"
        # r.set(key, json.dumps({'value': email}), ex=expiration)

        # print("flask.session['credentials'] : ", flask.session['credentials'])
        logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : {}".format(flask.session['credentials']))
        logger.LoggerFactory._LOGGER.info("flask.session['credentials']['id_token'] : {}".format(flask.session['credentials']['id_token']))
        
        return flask.redirect('/api/data')
    
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : {}".format(e))
        logger.LoggerFactory._LOGGER.info("시스템 관리자에게 연락하세요. 010-6434-3191")

        return ("시스템 관리자에게 연락하세요. 010-6434-3191")
    

@oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback_Redis():
    logger.LoggerFactory._LOGGER.info("oauth2callback_Session")

    try:
        # flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)
        

        flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
        
        authorization_response = flask.request.url
        
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials

        # 문자열을 datetime 객체로 변환
        expiration_time = credentials.expiry + datetime.timedelta(hours=9)

        if credentials.id_token:
            try:
                # id_token 디코딩
                decoded_token = jwt.decode(credentials.id_token, options={"verify_signature": False})

                # 사용자 정보 추출
                email = decoded_token.get('email')
                print(f"사용자 이메일: {email}")

            except jwt.ExpiredSignatureError:
                print("id_token이 만료되었습니다.")
            except jwt.InvalidTokenError:
                print("유효하지 않은 id_token입니다.")
            except Exception as e:
                print(f"id_token 디코딩 오류: {e}")
        else:
            print("id_token이 없습니다.")
        
        flask.session['credentials'] = {
            # 'token': credentials.token,
            # 'refresh_token': credentials.refresh_token,
            # 'token_uri': credentials.token_uri,
            # 'client_id': credentials.client_id,
            # 'client_secret': credentials.client_secret,
            # # 'expiry': credentials.expiry,
            # 'expiry': expiration_time,
            # 'id_token': credentials.id_token,
            'email': email,
            # 'granted_scopes': credentials.granted_scopes
        }
        logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : {}".format(flask.session['credentials']))

        data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            # 'expiry': credentials.expiry,
            # 'expiry': expiration_time,
            'expiry': expiration_time.isoformat(),
            'id_token': credentials.id_token,
            'email': email,
            'granted_scopes': credentials.granted_scopes
        }

        response = make_response(flask.redirect('http://localhost:3000/test'))
        # response = make_response(flask.redirect('http://localhost:8000/api/data'))
        # response = make_response(json.dumps(data))
        response.set_cookie("email", email)  # 쿠키 설정
        response.headers['X-User-Email'] = email  # 커스텀 헤더 추가

        logger.LoggerFactory._LOGGER.info("data : {}".format(data))
        
        r = redis.Redis(host='localhost', port=6379, db=0)
        expiration = 60  # 1분
        key = f"user:{email}:access_token"
        r.set(key, json.dumps({'value': data}), ex=expiration)

        return response
    
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : {}".format(e))
        logger.LoggerFactory._LOGGER.info("시스템 관리자에게 연락하세요. 010-6434-3191")

        return ("시스템 관리자에게 연락하세요. 010-6434-3191")


# def getTokenRefreshed():
def getTokenRefreshed(tokenSaveType): 
    print("getTokenRefreshed tokenSaveType : ", tokenSaveType)
    logger.LoggerFactory._LOGGER.info("getTokenRefreshed tokenSaveType : {}".format(tokenSaveType))


    # flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)

    # 예시: 토큰 갱신 요청
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": "1//0eNWSVI3Ne76QCgYIARAAGA4SNwF-L9Irw8pgj3Rv0OkPUihp15o5LHal08vGItK7bV0aFDlkeIFrSARMtjgyKqljhcTnnmAiDbo"
    }

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(token_url, data=json.dumps(token_data), headers=headers)
        response.raise_for_status()  # HTTP 오류 발생 시 예외 발생

        data = response.json()
        logger.LoggerFactory._LOGGER.info("oauth2callback_Session")
        
        if tokenSaveType == 'S':
            print("Session에 토큰 갱신 정보를 저장합니다.")
            logger.LoggerFactory._LOGGER.info("Session에 토큰 갱신 정보를 저장합니다.")

            flask.session['credentials'] = {
                'token': data["access_token"],
                # 'refresh_token': data["refresh_token"],
                'expiry': datetime.datetime.now() + datetime.timedelta(seconds=data["expires_in"])
                # 'granted_scopes': data["scope"]
            }

            # print("flask.session['credentials'] : ", flask.session['credentials'])
            logger.LoggerFactory._LOGGER.info("flask.session['credentials'] : ", flask.session['credentials'])

            return flask.session['credentials']
        
        elif tokenSaveType == 'C':
            # print("Cookie에 토큰 갱신 정보를 저장합니다.")
            logger.LoggerFactory._LOGGER.info("Cookie에 토큰 갱신 정보를 저장합니다.")
            resp = make_response(jsonify(data)) # 응답 json 데이터를 클라이언트로 보내기
            resp.set_cookie("access_token", data["access_token"])
            # if "token" in data:  # token 키가 존재하는지 확인
            #     resp.set_cookie("token", data["token"])
            resp.set_cookie("refresh_token_expires_in", str(data["refresh_token_expires_in"]))
            resp.set_cookie("expiry", str(datetime.datetime.now()))
            return resp
        
        elif tokenSaveType == 'R':
            # print("Redis에 토큰 갱신 정보를 저장합니다.")
            logger.LoggerFactory._LOGGER.info("Redis에 토큰 갱신 정보를 저장합니다.")

        else:
            # print("저장 타입을 지정하지 않았습니다.")
            logger.LoggerFactory._LOGGER.info("저장 타입을 지정하지 않았습니다.")

        

        # response.set_cookie("token", data["token"])
        # response.set_cookie("refresh_token", data["refresh_token"])
        # response.set_cookie("token", response.json()["token"])
        # response.set_cookie("refresh_token", response.json()["refresh_token"])
        
        # return response.json()
        # return resp

    except requests.exceptions.RequestException as e:
        # print(f"오류 발생: {e}")
        logger.LoggerFactory._LOGGER.info(f"오류 발생: {e}")

        if response is not None:
            # print(f"응답 내용: {response.text}")
            logger.LoggerFactory._LOGGER.info(f"응답 내용: {response.text}")
        return None
    
    except json.JSONDecodeError as e:
        # print(f"JSON 디코딩 오류: {e}, 응답 내용: {response.text}")
        logger.LoggerFactory._LOGGER.info(f"JSON 디코딩 오류: {e}, 응답 내용: {response.text}")
        return None

