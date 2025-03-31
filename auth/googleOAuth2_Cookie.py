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
from flask_cors import cross_origin

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

@oauth2Authorization.route('/', methods=['GET'])
def authorize(): 
    print("authorize()")
    # logger.LoggerFactory._LOGGER.info("authorize")

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
        # flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
        flow.redirect_uri = REDIRECT_URL
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

        flask.session['state'] = state
        print("authorization_url : ", authorization_url)

        return flask.redirect(authorization_url)
        # return jsonify({'authorizationUrl': authorization_url})
    
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : ", e)

        return ("시스텥 관리자에게 연락하세요.")


@oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback():
    print("oauth2callback()")
    # logger.LoggerFactory._LOGGER.info("oauth2callback()")

    flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)
    # flow.redirect_uri = 'http://localhost:8000/api/oauth2/code'
    flow.redirect_uri = REDIRECT_URL
    
    authorization_response = flask.request.url
    
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    # print(credentials.__dict__) # flow.credentials 내부 상세 속성 확인(중요)
    
    # response = make_response("쿠키 설정 완료!")
    # response = make_response(flask.redirect('/api/data'))
    response = make_response(flask.redirect('http://localhost:3000/test'))
    # response = make_response(flask.redirect('http://localhost:3000'))
    # response = make_response(response)
    # response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000/test")
    # response.headers.add("Access-Control-Allow-Credentials", "true")
    response.set_cookie("token", credentials.token)
    response.set_cookie("refresh_token", credentials.refresh_token)
    response.set_cookie("id_token", credentials.id_token)

    return response


def checkTokenValidation(token, refreshToken):
    print("checkTokenValidation()")
    print("token : ", token)
    # logger.LoggerFactory._LOGGER.info("checkTokenValidation()")
    """세션에 액세스 토큰 만료 시간이 있고 만료되었는지 확인합니다."""

    try:
        tokeninfo_url = 'https://oauth2.googleapis.com/tokeninfo'
        params = {'access_token': token}

        try:
            response = requests.get(tokeninfo_url, params=params)
            # response.raise_for_status()  # 상태 코드가 200 OK가 아니면 예외 발생
            token_info = response.json()
            print("token_info['expires_in'] : ", token_info['expires_in'])

            if int(token_info['expires_in']) > 3550:
                print("Access Token이 유효합니다.")
                return "Exist"
            else:
                # return "Error"
                # if cookies.get("refresh_token") is not None:
                if refreshToken is not None:
                    print("Access Token이 만료됐습니다.")
                    return "Expired"
                else:
                    print("*Refresh Token이 없습니다.")
                    return "Error"
            
        except requests.exceptions.RequestException as e:
            print(f"tokeninfo 요청 실패: {e}")
            return "Error"
        

# def checkTokenValidation():
#     print("checkTokenValidation()")
#     # logger.LoggerFactory._LOGGER.info("checkTokenValidation()")
#     """세션에 액세스 토큰 만료 시간이 있고 만료되었는지 확인합니다."""

#     try:
#         cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.
#         # print("request.url : ", request.url)
#         print("cookies : ", cookies)

#         if cookies.get("token") is not None:
#         # if cookies.get("id_token") is not None:
#             token = cookies.get("token")
#             # print("token : ", token)

#             # id_token = cookies.get("id_token")
#             # print("id_token : ", id_token)

#             """Google tokeninfo 엔드포인트를 사용하여 액세스 토큰의 유효성을 확인합니다."""
#             tokeninfo_url = 'https://oauth2.googleapis.com/tokeninfo'
#             params = {'access_token': token}

#             try:
#                 response = requests.get(tokeninfo_url, params=params)
#                 # response.raise_for_status()  # 상태 코드가 200 OK가 아니면 예외 발생
#                 token_info = response.json()
#                 # print("token_info : ", token_info)
#                 print("token_info['expires_in'] : ", token_info['expires_in'])

#                 if int(token_info['expires_in']) > 3550:
#                     print("Access Token이 유효합니다.")
#                     # return True
#                     # return 'http://localhost:8000/api/oauth2'
#                     return "Exist"
#                 else:
#                     # refresh_token = cookies.get("refresh_token")
#                     if cookies.get("refresh_token") is not None:
#                         print("Access Token이 만료됐습니다.")
#                         return "Expired"
#                     else:
#                         print("*Refresh Token이 없습니다.")
#                         return "Error"
                
#                 # 'error' 키가 없으면 토큰이 유효한 것으로 간주 (만료되었을 수도 있음)
#                 # if 'error' in token_info:
#                 #     print(f"액세스 토큰이 유효하지 않습니다: {token_info['error_description']}")
#                 #     result = getTokenRefreshed()
#                 #     return False
#                 # else:
#                 #     print("액세스 토큰 정보:", token_info)
#                 #     # 'expires_in' 값을 통해 만료 여부를 추가적으로 확인할 수 있습니다.
#                 #     return True
                
#             except requests.exceptions.RequestException as e:
#                 print(f"tokeninfo 요청 실패: {e}")
#                 # return False
#                 return "Error"

#         else:
#             # return False
#             return "Error"
    
    except Exception as e:
        print(f"checkTokenValidation() 오류: {e}")
        # logger.LoggerFactory._LOGGER.info("checkTokenValidation()")


def getTokenRefreshed():
    print("getTokenRefreshed()")
    # logger.LoggerFactory._LOGGER.info("getTokenRefreshed()")

    # flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)

    cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.

    if cookies.get("refresh_token") is not None:
        refresh_token = cookies.get("refresh_token")
    
    # 예시: 토큰 갱신 요청
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_SECRET['web']['client_id'],
        "client_secret": CLIENT_SECRET['web']['client_secret'],
        "refresh_token": refresh_token
    }

    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(token_url, data=json.dumps(token_data), headers=headers)
        # response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
        
        logger.LoggerFactory._LOGGER.info("Cookie에 토큰 갱신 정보를 저장합니다.")
        return response

    except requests.exceptions.RequestException as e:
        logger.LoggerFactory._LOGGER.info(f"오류 발생: {e}")

        if response is not None:
            logger.LoggerFactory._LOGGER.info(f"응답 내용: {response.text}")
        return None
    
    except json.JSONDecodeError as e:
        logger.LoggerFactory._LOGGER.info(f"JSON 디코딩 오류: {e}, 응답 내용: {response.text}")
        return None


# Google OAuth 2.0 환경에서 액세스 토큰을 취소하면 갱신 토큰도 함께 취소됨
@oauth2Authorization.route('/revoke', methods=['GET'])
def tokenRevoke():
    print("tokenRevoke()")
    # logger.LoggerFactory._LOGGER.info("tokenRevoke()")

    try:
        cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.

        if cookies.get("token") is not None:
            token = cookies.get("token")

            revoke_endpoint = 'https://oauth2.googleapis.com/revoke'
            params = {'token': token}
            headers = {'content-type': 'application/x-www-form-urlencoded'}

            try:
                response = requests.post(revoke_endpoint, params=params, headers=headers)
                response.raise_for_status()  # 응답 상태 코드가 200 OK가 아니면 예외 발생
                print(f"토큰 '{token[:20]}... (일부)' 취소 성공")
                return "Success"
                
            except requests.exceptions.RequestException as e:
                print(f"토큰 취소 요청 실패: {e}")
                return "Expired"
        
        else:
            return False
    
    except Exception as e:
        print(f"checkTokenValidation() 오류: {e}")
        return False
        # logger.LoggerFactory._LOGGER.info("checkTokenValidation()")