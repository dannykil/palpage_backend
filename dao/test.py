from flask import Flask, jsonify, Blueprint
from flask_cors import CORS
import psycopg2
import os

testData = Blueprint('testData', __name__, url_prefix='/api/data')

# 환경 변수 또는 보안 파일에서 데이터베이스 연결 정보 로드
# DB_HOST = os.environ.get('DB_HOST', 'your_db_host')
# DB_USER = os.environ.get('DB_USER', 'your_db_user')
# DB_PASSWORD = os.environ.get('DB_PASSWORD', 'your_db_password')
# DB_NAME = os.environ.get('DB_NAME', 'your_db_name')
DB_HOST = os.environ.get('DB_HOST', '35.193.181.248')
DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')
DB_NAME = os.environ.get('DB_NAME', 'postgres')
DB_PORT = os.environ.get('DB_PORT', 5432) # PostgreSQL 기본 포트

@testData.route('/', methods=['GET'])
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

        # print('rows : ', rows)

        return jsonify(rows)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)