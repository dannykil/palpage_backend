import google_auth_oauthlib.flow
import flask, requests
from flask import jsonify, request, make_response, Blueprint
import json
from common import logger, getEnv
from auth.secretManager import access_secret_version
from dao.refresh_token import insert_refresh_token, select_refresh_token, update_access_token
import jwt

REDIRECT_URL = getEnv.get_environment_variable('REDIRECT_URL')
CLIENT_SECRET = access_secret_version()

oauth2Authorization = Blueprint('oauth2Authorization', __name__, url_prefix='/api/oauth2')

SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly',
          'https://www.googleapis.com/auth/calendar.readonly',
          'openid', 
          'https://www.googleapis.com/auth/userinfo.email']

@oauth2Authorization.route('/', methods=['GET'])
def authorize(): 
    print("authorize()")
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

        # return flask.redirect(authorization_url)
        return jsonify({'authorizationUrl': authorization_url})
    
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : ", e)

        return ("시스텥 관리자에게 연락하세요.")


@oauth2Authorization.route('/code', methods=['GET'])
def oauth2callback():
    print("oauth2callback()")
    # logger.LoggerFactory._LOGGER.info("oauth2callback()")

    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_SECRET, scopes=SCOPES)
        flow.redirect_uri = REDIRECT_URL
        
        authorization_response = flask.request.url
        
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        # print("credentials : ", credentials)
        # print(credentials.__dict__) # flow.credentials 내부 상세 속성 확인(중요)

        id_token_jwt = credentials.id_token

        # JWT 디코딩 (서명 검증 없이)
        decoded_payload = jwt.decode(id_token_jwt, options={"verify_signature": False})
        print("Decoded Payload:", decoded_payload)

        # 디코딩된 페이로드에서 이메일 주소 추출
        email = decoded_payload.get('email')
        print("Extracted Email:", email)

        # 추가적인 검증 (만료 시간, 발행자, audience)을 수행해야 합니다.
        # 예시:
        # if decoded_payload.get('iss') != 'https://accounts.google.com' and decoded_payload.get('iss') != 'accounts.google.com':
        #     print("잘못된 발행자")
        #     return make_response("잘못된 발행자", 401)
        # if decoded_payload.get('aud') != CLIENT_SECRET['web']['client_id']:
        #     print("잘못된 Audience")
        #     return make_response("잘못된 Audience", 401)
        # # 만료 시간 검증은 더 복잡하게 구현해야 합니다.

        response = make_response(flask.redirect('http://localhost:3000/test'))
        response.set_cookie("token", credentials.token)
        # response.set_cookie("refresh_token", credentials.refresh_token)
        # response.set_cookie("id_token", id_token_jwt)
        # response.set_cookie("email", email)

        # if 'refresh_token' in request.cookies:
        #     response.delete_cookie('refresh_token')
        # if 'id_token' in request.cookies:
        #     response.delete_cookie('id_token')
        # if 'email' in request.cookies:
        #     response.delete_cookie('email')

        user_id = email # 이메일을 user_id로 사용
        insert_refresh_token(credentials.refresh_token, credentials.token, user_id, CLIENT_SECRET['web']['client_id'])
        return response

    except jwt.exceptions.DecodeError as e:
        print(f"JWT 디코딩 오류: {e}")
        return make_response("JWT 디코딩 오류", 401)
    
    except Exception as e:
        print(f"Access Token 생성 오류: {e}")
        return make_response("Access Token 생성 오류", 400)
    

def checkTokenValidation(token):
    print("checkTokenValidation(token)")
    # print("token : ", token)
    # logger.LoggerFactory._LOGGER.info("checkTokenValidation(token)")
    """세션에 액세스 토큰 만료 시간이 있고 만료되었는지 확인합니다."""

    try:
        tokeninfo_url = 'https://oauth2.googleapis.com/tokeninfo'
        params = {'access_token': token}

        response = requests.get(tokeninfo_url, params=params)
        # response.raise_for_status()  # 상태 코드가 200 OK가 아니면 예외 발생

        token_info = response.json()
        print("token_info['expires_in'] : ", token_info['expires_in'])

        if int(token_info['expires_in']) > 3550:
            print("Access Token이 유효합니다.")
            # return "Exist"
            return True
        
        else:
            # return "Expired"
            return False
    
    except Exception as e:
        print(f"checkTokenValidation() 오류: {e}")
        # return "Error"
        return False
        # logger.LoggerFactory._LOGGER.info("checkTokenValidation()")


def getTokenRefreshed(token):
    print("getTokenRefreshed(token)")
    # logger.LoggerFactory._LOGGER.info("getTokenRefreshed()")

    try: 
        refresh_token = select_refresh_token(token)

        if refresh_token:
            print("refresh_token : ", refresh_token[0])
        
            # 예시: 토큰 갱신 요청
            token_url = "https://oauth2.googleapis.com/token"
            token_data = {
                "grant_type": "refresh_token",
                "client_id": CLIENT_SECRET['web']['client_id'],
                "client_secret": CLIENT_SECRET['web']['client_secret'],
                "refresh_token": refresh_token[0]
            }

            try:
                headers = {'Content-Type': 'application/json'}
                response = requests.post(token_url, data=json.dumps(token_data), headers=headers)
                response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
                
                # logger.LoggerFactory._LOGGER.info("Cookie에 토큰 갱신 정보를 저장합니다.")
                # print("Cookie에 토큰 갱신 정보를 저장합니다. : ", response.json().get('access_token'))
                print("Access Token이 갱신되었습니다. ")
                print("Before Access Token : ", token)
                print("After  Access Token : ", response.json().get('access_token'))

                result = update_access_token(response.json().get('access_token'), refresh_token[0])

                if result:
                    # print("Access Token이 갱신되었습니다.")
                    return response.json().get('access_token')
                else:
                    print("Access Token 갱신 실패")
                    return None

                # return response
                # return response.json().get('access_token')

            except requests.exceptions.RequestException as e:
                # logger.LoggerFactory._LOGGER.info(f"오류 발생: {e}")
                print(f"오류 발생: {e}")

                if response is not None:
                    # logger.LoggerFactory._LOGGER.info(f"응답 내용: {response.text}")
                    print(f"응답 내용: {response.text}")
                return None
            
            except json.JSONDecodeError as e:
                # logger.LoggerFactory._LOGGER.info(f"JSON 디코딩 오류: {e}, 응답 내용: {response.text}")
                print(f"JSON 디코딩 오류: {e}, 응답 내용: {response.text}")
                return None

        else:
            print("Failed to retrieve refresh token.")
            return None
    
    except Exception as e:
        print(f"refresh_token 조회 오류: {e}")
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