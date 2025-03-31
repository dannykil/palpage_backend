from flask import Flask, jsonify, Blueprint, request
import psycopg2
import os

# testData = Blueprint('testData', __name__, url_prefix='/api/data')
testData = Blueprint('testData', __name__)

# 환경 변수 또는 보안 파일에서 데이터베이스 연결 정보 로드
DB_HOST = os.environ.get('DB_HOST', '35.193.181.248')
DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')
DB_NAME = os.environ.get('DB_NAME', 'postgres')
DB_PORT = os.environ.get('DB_PORT', 5432) # PostgreSQL 기본 포트

# @testData.route('/', methods=['GET'])
@testData.route('/api/data', methods=['GET'])
@testData.route('/api/data/', methods=['GET'])
def get_test_data():
    
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

        response = jsonify({"rows": rows})
        # response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000/test")
        # response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
