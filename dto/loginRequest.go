package dto

//ログインリクエストは、ユーザーネームとパスワードの二つ。
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}