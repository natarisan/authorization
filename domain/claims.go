package domain

import(
	"time"
	"github.com/dgrijalva/jwt-go"
)

const HMAC_SAMPLE_SECRET = "hmacsamplesecret"
const ACCESS_TOKEN_DURATION = time.Hour //1時間やな

type AccessTokenClaims struct {
	CustomerId string `json:"customer_id"`
	Accounts   []string `json:"accounts"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	jwt.StandardClaims
}

//ロールがユーザか管理者か？トークンの中に入っているものを確かめる
func(c AccessTokenClaims) IsUserRole() bool {
	return c.Role == "user"
}
//アカウントIDがちゃんとしてる？トークンの中の情報を解読している。アカウントIDとトークンの中に入っているアカウントIDが一致することを確かめる
func(c AccessTokenClaims) IsValidAccountId(accountId string) bool {
	if accountId != "" {
		accountFound := false
		for _, a := range c.Accounts {
			if a == accountId {
				accountFound = true
				break
			}
		}
		return accountFound
	}
	return true
}

//アカウントIDとカスタマーIDがちゃんとしてる？トークンの中の情報とURLパラメータの中の情報が一致することを確かめる。
func(c AccessTokenClaims) IsRequestVerifiedWithTokenClaims(urlParams map[string]string) bool {
	if c.CustomerId != urlParams["customer_id"] {
		return false
	}
	if !c.IsValidAccountId(urlParams["account_Id"]) {
		return false
	}
	return true
}