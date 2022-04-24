package dto

import(
	"errors"
	"auth/domain"
	"github.com/dgrijalva/jwt-go"
)

type RefreshToken struct {
	AccessToken   string `json:"access_token"`
	RefreshToken  string `json:"refresh_token"`
}

//無効なトークンか、有効だが期限切れのトークン
func(r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {
	_, err := jwt.Parse(r.AccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}