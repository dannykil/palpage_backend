from flask import Flask, jsonify, request, redirect, Blueprint, make_response
from flask_cors import CORS
# from auth.googleOAuth2 import oauth2Authorization, checkAuthorization
from auth.googleOAuth2_Cookie import oauth2Authorization, checkTokenValidation, getTokenRefreshed
from dao.test import testData
import secrets
import os 
from common import logger
import requests
import json

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})
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
            print("cookies.get('token') : ", cookies.get("token"))
            print("cookies.get('refresh_token') : ", cookies.get("refresh_token"))

            accessToken = cookies.get("token")
            refreshToken = cookies.get("refresh_token")
            # if request.headers.get('Authorization') is not None:
            #     print("request.headers.get('Authorization') : ", request.headers.get('Authorization'))
            #     accessToken = request.headers.get('Authorization')

            # Exist   : 새로 생성
            # Expired : 갱신
            # Error   : 갱신 > 새로 생성
            # result = checkTokenValidation()
            result = checkTokenValidation(accessToken, refreshToken)

            if result == "Exist":
                print("Exist")
            
            elif result == "Expired":
                response = getTokenRefreshed()

                if response is not None:
                    print("Expired")
                    # print("response : ", response)
                    resp = make_response(redirect(request.url))
                    data = response.json()
                    resp.set_cookie("token", data["access_token"])
                    resp.headers.add("Access-Control-Allow-Credentials", "true")
                    return resp
                else:
                    print("None")
                    return redirect('http://localhost:8000/api/oauth2')
            
            else:
                print("Error")
                return redirect('http://localhost:8000/api/oauth2')
            
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : {}".format(e))
        # return ("시스템 관리자에게 연락하세요.")
        return redirect('http://localhost:8000/api/oauth2')

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=8000, debug=True)
    app.run(debug=True, port=8000)