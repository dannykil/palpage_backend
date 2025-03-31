import pytest
import requests

# http://localhost:8000/api/data
# BASE_URL = 'http://127.0.0.1:8000' # API 기본 URL (실제 API URL로 변경)
BASE_URL = 'http://localhost:8000' # API 기본 URL (실제 API URL로 변경)

def test_api_success():
    # response = requests.get(f'{BASE_URL}/api/data')
    # response = requests.get("http://localhost:8000/api/test")
    response = requests.get("http://localhost:8000/api/data")
    print(response.json()[0]['id'])
    print(response.status_code)
    assert response.json()[0]['id'] == 1
    assert response.status_code == 200
    # assert response.json()['message'] == 'success'
    # assert response.json()['status'] == 200
    # return response

def test_api_failure():
    response = requests.get(f'{BASE_URL}/api/invalid') # 존재하지 않는 API 경로
    print(response.status_code)
    assert response.status_code == 404

def test_api_post_method():
    response = requests.post(f'{BASE_URL}/api/test') # 잘못된 요청 메소드
    print(response.status_code)
    assert response.status_code == 405

# test_api_success()
# test_api_failure()
# test_api_post_method()