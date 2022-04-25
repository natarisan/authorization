package domain

import(
	"github.com/natarisan/gop-libs/errs"
	"github.com/natarisan/gop-libs/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthToken struct {
	token *jwt.Token
}

func(t AuthToken) NewAccessToken()(string, *errs.AppError) {
	signedString, err := t.token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil {
		logger.Error("アクセストークン作成失敗!" + err.Error())
		return "", errs.NewUnexpectedError("アクセストークン作成失敗!")
	}
	return signedString, nil
}

func(t AuthToken) NewRefreshToken() (string, *errs.AppError){
	c := t.token.Claims.(AccessTokenClaims)
	refreshClaims := c.RefreshTokenClaims()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedString, err := token.SignedString([]byte(HMAC_SAMPLE_SECRET))
	if err != nil{
		logger.Error("リフレッシュトークンへのサインの付与に失敗しました" + err.Error())
		return "", errs.NewUnexpectedError("リフレッシュトークンを生み出せませんでした")
	} 
	return signedString, nil
}

func NewAuthToken(claims AccessTokenClaims) AuthToken {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return AuthToken {
		token: token,
	}
}

func NewAccessTokenFromRefreshToken(refreshToken string)(string, *errs.AppError){
	token, err := jwt.ParseWithClaims(refreshToken, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		return "", errs.NewAuthenticationError("invalid or expired refresh token")
	}
	r := token.Claims.(*RefreshTokenClaims)
	accessTokenClaims := r.AccessTokenClaims()
	authToken := NewAuthToken(accessTokenClaims)

	return authToken.NewAccessToken()
}