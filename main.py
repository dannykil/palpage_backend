from flask import Flask, jsonify, request, redirect, Blueprint
from flask_cors import CORS
# from auth.googleOAuth2 import oauth2Authorization, authorize, checkAuthorization_Session, checkAuthorization_Cookies, checkAuthorization
from auth.googleOAuth2 import oauth2Authorization, checkAuthorization
# from auth.googleOAuth2 import oauth2Authorization
from dao.test import testData
import secrets
import os 
from common import logger
# from common.logger2 import setup_logger

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.register_blueprint(testData)
app.register_blueprint(oauth2Authorization)

CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# app.secret_key = 'REPLACE ME - this value is here as a placeholder.'
app.secret_key = secrets.token_hex(16)

logger.LoggerFactory.create_logger()
# logger = setup_logger()


# 인증, 로깅, 유효성 검사 등의 작업 수행 - API 요청 시작 전 무조건 실행
# 필요에 따라 request를 수정하거나 abort()하여 요청 처리를 중단할 수 있습니다.
@app.before_request
def specific_api_filter():
    # print("Filter")
    logger.LoggerFactory._LOGGER.info("Filter")
    # logger.LoggerFactory._LOGGER.warning("Filter")
    # print("request.path : ", request.path)
    # print("request : ", request)
    # print("not request.path.startswith('/api/oauth2') : ", not request.path.startswith('/api/oauth2'))

    try:
        # /api/oauth2로 시작하지 않는 요청에 대해서만 인증 검사
        if not request.path.startswith('/api/oauth2'):

            # tokenSaveType = 'S' : Session
            # tokenSaveType = 'C' : Cookie
            # tokenSaveType = 'R' : Redis
            result = checkAuthorization('R')
            # result = checkAuthorization_Session()
            # result = checkAuthorization_Cookies()

            # E : 토큰이 존재하는 경우(Exist)            >>> 원래 페이지로 이동
            # R : 토큰 만료 후 갱신이 필요한 경우(Refresh) >>> (갱신 후)원래 페이지로 이동
            # F : 최초 인증이 필요한 경우(First)         >>> http://localhost:8000/api/oauth2
            if result == 'E':
                print("result : ", result)
                # return jsonify({'result': result})
                # return redirect('http://localhost:8000', request.path)
                # print("path : ", 'http://localhost:8000{}'.format(request.path))
                # return redirect('http://localhost:8000{}'.format(request.path))
                # return redirect('http://localhost:8000/api/data')
                # return False
                # return redirect('http://localhost:8000{}'.format(request.path))
            elif result == 'R':
                print("result : ", result)
                # return jsonify({'result': result})
                # return redirect('http://localhost:8000/api/oauth2')
                # return redirect('http://localhost:8000/api/data')
                # return redirect('http://localhost:8000{}'.format(request.path))
            else:
                print("result : ", result)
                # return jsonify({'result': result})
                return redirect('http://localhost:8000/api/oauth2')
                # return redirect('http://localhost:8000{}'.format(request.path))
    except Exception as e:
        logger.LoggerFactory._LOGGER.info("에러발생 : {}".format(e))

        return ("시스텥 관리자에게 연락하세요.")

        # if not result: 
        #     print("result : ", result)
        #     # return jsonify({'result': result})
        #     return redirect('http://localhost:8000/api/oauth2')


# @app.route('/api/hello', methods=['GET'])
# def hello():
#     # print("request.url : ", request.url)
#     #     return jsonify({'message': 'Hello, World!'})

#     # result = checkAuthorization(request.url)
#     result = checkAuthorization()
#     print("result : ", result)

#     if result:
#         return jsonify({'message': 'Hello, World!'})
    
#     else:
#         return ('You need to <a href="/api/oauth2">Log In</a> before ' +
#                 'testing the code to revoke credentials.')

# @app.route('/api/oauth2', methods=['GET'])
# def get_auth_route(): 
#     return authorize()   

# @app.route('/api/oauth2/code', methods=['GET'])
# # def get_code_route(): return oauth2callback()
# def get_code_route(): return oauth2callback_cookie()

# @app.route('/api/logout', methods=['GET'])
# def get_logout_route(): return logout()

# @app.route('/login', methods=['GET'])
# def get_login_route(): return login()

# @app.route('/api/data', methods=['GET'])
# def get_data_route(): return get_test_data()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)