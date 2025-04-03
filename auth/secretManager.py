from google.cloud import secretmanager

# secret_id = "8page-client-secret"
# project_id = "gen-lang-client-0274842719"

# def access_secret_version(secret_id, project_id="your-gcp-project-id"):
def access_secret_version():
    """액세스 지정된 Secret의 최신 버전."""

    # Secret Manager 클라이언트 생성
    client = secretmanager.SecretManagerServiceClient()

    # Secret 버전 이름 구성
    # secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    secret_name = f"projects/gen-lang-client-0274842719/secrets/8page-client-secret/versions/latest"

    # Secret 버전 접근
    response = client.access_secret_version(request={"name": secret_name})

    # 페이로드 추출 및 디코딩
    payload = response.payload.data.decode("UTF-8")
    # print("payload : ", payload)

    import json    
    client_config = json.loads(payload)
    # print(f"Client client_config     : {client_config}")

    # client_id와 client_secret 추출
    # client_id = client_config['web']['client_id']
    # client_secret = client_config['web']['client_secret']

    print("Secret Manager에서 client_secret.json 로드 성공:")
    # print(f"Client ID     : {client_id}")

    # return payload
    return client_config