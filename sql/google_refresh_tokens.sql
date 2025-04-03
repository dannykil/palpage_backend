CREATE TABLE google_refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL, -- 사용자 테이블의 기본 키를 참조 (예시)
    refresh_token TEXT NOT NULL UNIQUE,
    access_token TEXT NULL, -- 현재 유효한 액세스 토큰 (선택 사항, 보안상 고려 필요)
    -- token_type VARCHAR(50) NULL,
    expiry_timestamp TIMESTAMP WITH TIME ZONE NULL, -- 액세스 토큰 만료 시간
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    scope TEXT NULL, -- 부여된 스코프 목록 (공백 또는 쉼표로 구분)
    client_id VARCHAR(255) NULL, -- OAuth 2.0 클라이언트 ID (어떤 앱에서 발급했는지)
    revoked BOOLEAN DEFAULT FALSE NOT NULL -- 토큰 무효화 여부

    -- user_id 컬럼이 users 테이블의 id 컬럼을 참조하는 외래 키 설정 (가정)
    -- 필요에 따라 ON DELETE 옵션을 조정하세요 (CASCADE, SET NULL 등)
    -- FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- refresh_token 컬럼에 대한 인덱스 생성 (빠른 조회를 위해)
CREATE INDEX idx_google_refresh_tokens_refresh_token ON google_refresh_tokens (refresh_token);

-- user_id 컬럼에 대한 인덱스 생성 (특정 사용자의 토큰 조회)
CREATE INDEX idx_google_refresh_tokens_user_id ON google_refresh_tokens (user_id);

-- revoked 컬럼에 대한 인덱스 생성 (유효한 토큰 조회)
CREATE INDEX idx_google_refresh_tokens_revoked ON google_refresh_tokens (revoked);