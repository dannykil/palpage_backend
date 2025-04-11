import psycopg2
from common import getEnv
from datetime import datetime
import requests

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
def insert_refresh_token(new_refresh_token, access_token, user_id, client_id):
    print("insert_refresh_token()")
    # logger.LoggerFactory._LOGGER.info("insert_refresh_token()")
    # 1) 기존 refresh_token 조회(배열)
    # 2) 기존 refresh_token 취소(반복문 - api 호출)
    # 3) 기존 refresh_token 취소 후 상태 업데이트(update 쿼리)
    # 4) 신규 refresh_token 추가(insert 쿼리)

    # refresh_token = "1//0ekPvmg6LkAfgCgYIARAAGA4SNwF-L9Irla5Fs_CnWWKbWpLqfdBXYvlgDIGXnk32gCMdtvs3zrXy9nyBXgzk4cclIRhVGb9oVIY" # 실제 리프레시 토큰 값으로 변경
    # user_id = "jm.kil@hist.co.kr" # 실제 이메일 주소로 변경
    # expires_at = None  # 만료 시간 (선택 사항, None으로 설정하면 NULL로 들어감)
    # last_used_at = None
    # refresh_token = ""
    # access_token
    # user_id
    # client_id


    # # 1. 특정 사용자의 revoked=true인 refresh_token 목록 가져오기
    # refresh_tokens = get_refresh_tokens_by_user(user_id)

    # # 2. 가져온 refresh_token들을 반복하며 revoke_refresh_token 함수 호출
    # # print(f"\nAttempting to revoke refresh tokens for user '{user_id}':")
    # for refresh_token in refresh_tokens:
    #     revoke_success = revoke_refresh_token(refresh_tokens)

    #     if revoke_success:
    #         print(f"Successfully (re-)attempted to revoke token: {refresh_token}")

    #         # 3. 정상적으로 취소된 refresh_token에 대해 revoked=true로 업데이트
    #         update_revoked_status(refresh_token, user_id, revoked=True)

    #     else:
    #         print(f"Failed to (re-)attempt to revoke token: {refresh_token}")
        
    #         # 3-1. 실패해도 refresh_token에 대해 revoked=true로 업데이트 = 이미 revoked 상태일 수 있음
    #         update_revoked_status(refresh_token, user_id, revoked=True)

    # 4. 신규 refresh_token 추가(insert 쿼리)
    """google_refresh_tokens 테이블에 데이터를 삽입합니다."""
    conn = connect_to_db()
    if not conn:
        return
    
    insert_query = f"""
    INSERT INTO {TABLE_NAME} (refresh_token, access_token, user_id, created_at, updated_at, client_id)
    VALUES (%s, %s, %s, %s, %s, %s);
    """

    created_at = datetime.now()
    updated_at = datetime.now()

    try:
        with conn.cursor() as cur:
            cur.execute(insert_query, (new_refresh_token, access_token, user_id, created_at, updated_at, client_id))
            conn.commit()
            print("Refresh token inserted successfully.")
            return True
        
    except psycopg2.Error as e:
        print(f"Error inserting refresh token: {e}")
        conn.rollback()
        return False


# 1. 특정 사용자의 revoked=false인 refresh_token 목록 가져오기
def get_refresh_tokens_by_user(user_id):
    print("get_refresh_tokens_by_user()")
    """주어진 user_id에 대해 revoked가 false인 refresh_token들을 배열로 가져옵니다."""

    conn = connect_to_db()
    if not conn:
        return []

    select_query = f"""
    SELECT refresh_token FROM {TABLE_NAME} WHERE user_id = %s AND revoked = false;
    """

    try:
        rows = fetch_data(conn, select_query, (user_id,))
        refresh_tokens = [row[0] for row in rows]
        print(f"Found revoked refresh tokens for user '{user_id}': {refresh_tokens}")
        return refresh_tokens
    
    except psycopg2.Error as e:
        print(f"Error fetching revoked refresh tokens: {e}")
        return []
    
    finally:
        if conn:
            conn.close()
            print("Database connection closed")


# 2. 가져온 refresh_token들을 반복하며 revoke_refresh_token 함수 호출
def revoke_refresh_token(refresh_token):
    print("revoke_refresh_token()")
    """주어진 refresh_token을 Google API를 통해 취소합니다."""

    if not refresh_token:
        print("No refresh token to revoke.")
        return False

    params = {'token': refresh_token}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post("https://oauth2.googleapis.com/revoke", params=params, headers=headers)
        response.raise_for_status()  # HTTP 오류 발생 시 예외 발생
        print(f"Refresh token '{refresh_token}' revoked successfully.")
        return True
    
    except requests.exceptions.RequestException as e:
        print(f"Error revoking refresh token '{refresh_token}': {e}")

        if response is not None:
            print(f"Revoke response content: {response.text}")
        return False
    

# 3. 정상적으로 취소된 refresh_token에 대해 revoked=true로 업데이트
def update_revoked_status(refresh_token, user_id, revoked=True):
    print
    """주어진 refresh_token의 revoked 칼럼을 업데이트합니다."""

    conn = connect_to_db()
    if not conn:
        return False

    updated_at = datetime.now()

    update_query = f"""
    UPDATE {TABLE_NAME} SET revoked = %s, updated_at = %s WHERE refresh_token = %s and user_id = %s;
    """

    try:
        with conn.cursor() as cur:
            cur.execute(update_query, (revoked, updated_at, refresh_token, user_id))
            conn.commit()

            if cur.rowcount > 0:
                print(f"Revoked status updated to {revoked} for refresh token: {refresh_token}")
                return True
            else:
                print(f"No record found with refresh token: {refresh_token} to update revoked status.")
                return False

    except psycopg2.Error as e:
        print(f"Error updating revoked status: {e}")
        conn.rollback()
        return False

    finally:
        if conn:
            conn.close()
            print("Database connection closed")


def select_refresh_token(access_token):    
    print("select_refresh_token()")
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


def update_access_token(access_token, refresh_token):
    """주어진 refresh_token에 해당하는 access_token을 새로운 값으로 업데이트합니다."""

    conn = connect_to_db()
    if not conn:
        return False

    updated_at = datetime.now()

    update_query = f"""
    UPDATE {TABLE_NAME} SET access_token = %s, updated_at = %s WHERE refresh_token = %s;
    """

    try:
        with conn.cursor() as cur:
            cur.execute(update_query, (access_token, updated_at, refresh_token))
            conn.commit()
            if cur.rowcount > 0:
                print(f"Access Token updated successfully : {access_token}")
                return True
            else:
                print(f"No record found with Refresh Token : {refresh_token}")
                return False
            
    except psycopg2.Error as e:
        print(f"Error updating refresh token: {e}")
        conn.rollback()
        return False
    
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