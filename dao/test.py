from flask import Flask, jsonify, Blueprint, request
import psycopg2
import os
from common import logger, getEnv

# testData = Blueprint('testData', __name__, url_prefix='/api/data')
testData = Blueprint('testData', __name__)

# 환경 변수 또는 보안 파일에서 데이터베이스 연결 정보 로드
DB_HOST     = getEnv.get_environment_variable('DB_HOST')
DB_USER     = getEnv.get_environment_variable('DB_USER')
DB_PASSWORD = getEnv.get_environment_variable('DB_PASSWORD')
DB_NAME     = getEnv.get_environment_variable('DB_NAME')
DB_PORT     = getEnv.get_environment_variable('DB_PORT')

# @testData.route('/', methods=['GET'])
@testData.route('/api/data', methods=['GET'])
@testData.route('/api/data/', methods=['GET'])
def get_test_data():
    # logger.LoggerFactory._LOGGER.info("get_test_data()")
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            dbname=DB_NAME,
            port=DB_PORT
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM test")
        # rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description] # 컬럼 이름 가져오기
        rows = [dict(zip(columns, row)) for row in cur.fetchall()] # key:value 형태로 변환
        cur.close()
        conn.close()

        print('rows : ', rows)
        # logger.LoggerFactory._LOGGER.info("rows : {}".format(rows))

        response = jsonify({"rows": rows})
        # response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000/test")
        # response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# from flask import Flask, jsonify
# from flask_cors import CORS
import json
# import os
from datetime import datetime

# app = Flask(__name__)
# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})

# file_handler = logging.FileHandler('./log/' + datetime.now().strftime('%Y') + '/' + datetime.now().strftime('%m') + '/' + datetime.now().strftime('%Y%m%d') +'.log')
# LOG_FILE_PATH = 'your_log_file.json'  # 실제 로그 파일 경로로 변경
LOG_FILE_PATH = './log/' + datetime.now().strftime('%Y') + '/' + datetime.now().strftime('%m') + '/' + datetime.now().strftime('%Y%m%d') +'.log'

@testData.route('/api/logs', methods=['GET'])
@testData.route('/api/logs/', methods=['GET'])
def get_logs():
    print("get_logs()")
    print("LOG_FILE_PATH : ", LOG_FILE_PATH)

    try:
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                try:
                    logs = [json.loads(line) for line in f]
                    # print("logs : ", logs)
                    # return jsonify(logs)
                    # return jsonify({"rows": logs})
                    response = jsonify({"rows": logs})
                    response.headers.add("Access-Control-Allow-Credentials", "true")
                    return response
                except json.JSONDecodeError as e:
                    return jsonify({"error": f"JSON decoding error in log file: {e}"}), 500
        else:
            return jsonify({"error": f"Log file not found at: {LOG_FILE_PATH}"}), 404
    except Exception as e:
        return jsonify({"error": f"Error reading log file: {e}"}), 500

# if __name__ == '__main__':
#     app.run(debug=True, port=8000)
# get_test_data()