import psycopg2
from common import getEnv
from datetime import datetime

# 환경 변수 또는 보안 파일에서 데이터베이스 연결 정보 로드
DB_HOST     = getEnv.get_environment_variable('DB_HOST')
DB_USER     = getEnv.get_environment_variable('DB_USER')
DB_PASSWORD = getEnv.get_environment_variable('DB_PASSWORD')
DB_NAME     = getEnv.get_environment_variable('DB_NAME')
DB_PORT     = getEnv.get_environment_variable('DB_PORT')

# 테이블 이름
TABLE_NAME = "google_refresh_tokens"

def connect_to_db():
    """Cloud SQL PostgreSQL 데이터베이스에 연결합니다."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        print("Database connection successful")
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        return None


def fetch_data(conn, query, params=None):
    """데이터를 조회합니다."""
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            return rows
    except psycopg2.Error as e:
        print(f"Data retrieval error: {e}")
        return None


def delete_data(conn, query, params=None):
    """데이터를 삭제합니다."""
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            conn.commit()
            print(f"Deleted {cur.rowcount} row(s)")
            return True
    except psycopg2.Error as e:
        print(f"Data deletion error: {e}")
        conn.rollback()
        return False


def update_data(conn, query, params=None):
    """데이터를 업데이트합니다."""
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            conn.commit()
            print(f"Updated {cur.rowcount} row(s)")
            return True
    except psycopg2.Error as e:
        print(f"Data update error: {e}")
        conn.rollback()
        return False


# def insert_refresh_token(conn, refresh_token, email, expires_at=None, last_used_at=None):
def insert_refresh_token(refresh_token, access_token, user_id, client_id):
    # logger.LoggerFactory._LOGGER.info("insert_refresh_token()")
    """google_refresh_tokens 테이블에 데이터를 삽입합니다."""

    conn = connect_to_db()
    if not conn:
        return

    # refresh_token = "1//0ekPvmg6LkAfgCgYIARAAGA4SNwF-L9Irla5Fs_CnWWKbWpLqfdBXYvlgDIGXnk32gCMdtvs3zrXy9nyBXgzk4cclIRhVGb9oVIY" # 실제 리프레시 토큰 값으로 변경
    # user_id = "jm.kil@hist.co.kr" # 실제 이메일 주소로 변경
    # expires_at = None  # 만료 시간 (선택 사항, None으로 설정하면 NULL로 들어감)
    # last_used_at = None
    # refresh_token = ""
    # access_token
    # user_id
    created_at = datetime.now()
    updated_at = datetime.now()
    # client_id

    insert_query = f"""
    INSERT INTO {TABLE_NAME} (refresh_token, access_token, user_id, created_at, updated_at, client_id)
    VALUES (%s, %s, %s, %s, %s, %s);
    """

    try:
        with conn.cursor() as cur:
            cur.execute(insert_query, (refresh_token, access_token, user_id, created_at, updated_at, client_id))
            conn.commit()
            print("Refresh token inserted successfully.")
            return True
    except psycopg2.Error as e:
        print(f"Error inserting refresh token: {e}")
        conn.rollback()
        return False


def select_refresh_token(access_token):    
    conn = connect_to_db()
    if not conn:
        return

    try:
        # select_query_with_condition = f"SELECT * FROM {TABLE_NAME} WHERE refresh_token = %s"  # id 필드가 있다고 가정
        select_query_with_condition = f"SELECT refresh_token FROM {TABLE_NAME} WHERE access_token = %s"
        rows_with_id_1 = fetch_data(conn, select_query_with_condition, (access_token,))  # 튜플 형태로 파라미터 전달
        if rows_with_id_1:
            # print("Data with ID 1:")
            for row in rows_with_id_1:
                print(row)
        
            return row
    
    finally:
        if conn:
            conn.close()
            print("Database connection closed")


def main():
    """Cloud SQL PostgreSQL 예제."""
    conn = connect_to_db()
    if not conn:
        return

    try:
        # 1. 데이터 조회 예시
        select_query = f"SELECT * FROM {TABLE_NAME}"
        all_rows = fetch_data(conn, select_query)
        if all_rows:
            print("All data:")
            for row in all_rows:
                print(row)
    finally:
        if conn:
            conn.close()
            print("Database connection closed")


# if __name__ == "__main__":
#     main()
#     # select_refresh_token()
#     insert_refresh_token()