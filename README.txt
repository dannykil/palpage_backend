
- 가상환경 사용법
1) 가상환경 조회
conda info --envs
conda env list

2) 가상환경 생성
conda create -n 8page python=3.12

3) 가상환경 활성화
conda activate 8page

4) 가상환경 비활성화
conda deactivate

5) 가상환경 삭제
conda remove -n 8page --all

6) 가상환경 내 패키지 설치
conda install <패키지명>
pip install -r requirements.txt

7) 가상환경 내 설치된 패키지 추출
pip freeze > requirements.txt


- 사용자 정보 및 세션관리 개발(현재 서버 재부팅 시 세션 초기화됨)


# 개발 환경
ENV=dev python main.py

# 운영 환경
ENV=prd python main.py


which python
/opt/anaconda3/envs/8page_backend/bin/python


# redis container 사용법
1) container 접속
docker exec -it 03af7f472d81 /bin/bash

2) redis-cli 접속
redis-cli

3) test(생성된 key 전체목록 조회)
keys *