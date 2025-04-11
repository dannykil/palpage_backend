from flask import Flask, jsonify, request, redirect, Blueprint, make_response
from flask_cors import CORS
# from auth.googleOAuth2 import oauth2Authorization, checkAuthorization
from auth.googleOAuth2_Cookie import authorize, oauth2Authorization, checkTokenValidation, getTokenRefreshed
# from auth.googleOAuth2_Redis import oauth2Authorization, checkTokenValidation, getTokenRefreshed
from dao.test import testData
import secrets
import os 
from common import logger
import requests
import json

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000", "supports_credentials": True}})

app.register_blueprint(testData)
app.register_blueprint(oauth2Authorization)
app.secret_key = secrets.token_hex(16)
app.url_map.strict_slashes = False  # 마지막 슬래시 엄격하게 구분하지 않음

logger.LoggerFactory.create_logger()

# 인증, 로깅, 유효성 검사 등의 작업 수행 - API 요청 시작 전 무조건 실행
# 필요에 따라 request를 수정하거나 abort()하여 요청 처리를 중단할 수 있습니다.
@app.before_request
def specific_api_filter():
    print("Filter")
    # logger.LoggerFactory._LOGGER.info("Filter")
    print("request.path : ", request.path)

    try:
        # /api/oauth2로 시작하지 않는 요청에 대해서만 인증 검사
        if not request.path.startswith('/api/oauth2'):
            print("request.url : ", request.url)
            # print("request.method : ", request.method)
            # print("request.headers : ", request.headers)
            
            cookies = request.cookies  # 모든 쿠키 값을 딕셔너리 형태로 가져옵니다.

            if cookies.get("token") is not None:
                token = cookies.get("token")

                result = checkTokenValidation(token)

                if result == False:
                    print("access token is expired")
                    new_access_token = getTokenRefreshed(token)

                    if new_access_token is not None:
                        print("access token is refreshed")
                        response = make_response(redirect(request.url))
                        response.set_cookie("token", new_access_token)
                        response.headers.add("Access-Control-Allow-Credentials", "true")

                        return response
                    
                    # 액세스토큰 갱신 불가
                    else:
                        print("access token cannot be refreshed")
                        response = make_response(jsonify({'result': False, 'message': 'access token cannot be refreshed'}), 401)
                        response.headers.add("Access-Control-Allow-Credentials", "true")

                        return response
            
            # 쿠키에 토큰이 없는 경우
            else:
                print("No token in cookie")
                # resp = make_response(redirect(request.url))
                resp = make_response(redirect('http://localhost:8000/api/oauth2'))

                return resp
                # resp = make_response(redirect(request.url))
                # return resp
                # return redirect('http://localhost:8000/api/oauth2')
                # try:
                #     # response = requests.get('http://localhost:8000/api/oauth2')
                #     # response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
                #     response = authorize()
                #     print("response : ", response)

                #     data = response.json()
                #     print("data : ", data)

                #     authorization_url = data.get('authorizationUrl')
                #     return authorization_url
                
                # except requests.exceptions.RequestException as e:
                #     print(f"Error calling API: {e}")
                #     return None
            
    except Exception as e:
        # logger.LoggerFactory._LOGGER.info("에러발생 : {}".format(e))
        print("에러발생 : {}".format(e))
        # return ("시스템 관리자에게 연락하세요.")
        # return jsonify({'authorizationUrl': 'http://localhost:8000/api/oauth2'})
        # return redirect('http://localhost:8000/api/oauth2')
        
        try:
            # response = requests.get('http://localhost:8000/api/oauth2')
            # response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
            # data = response.json()
            response = authorize()
            print("response : ", response)
            data = response.json()
            print("data : ", data)
            authorization_url = data.get('authorizationUrl')
            return authorization_url
        
        except requests.exceptions.RequestException as e:
            print(f"Error calling API: {e}")
            return None

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=8000, debug=True)
    app.run(debug=True, port=8000)