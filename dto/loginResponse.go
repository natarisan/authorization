package dto

//ログイン成功時のトークンを返す。
type LoginResponse struct{
	AccessToken string `json:"access_token"`
}