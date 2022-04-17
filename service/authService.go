package service

import(
	"fmt"
	"AUTH/domain"
	"AUTH/dto"
	"github.com/natarisan/gop-libs/errs"
	"github.com/natarisan/gop-libs/logger"
	"github.com/dgrijalva/jwt-go"
)

//このサービスは３つのメソッドを実装する。
type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) //dtoのリクエストを受け取って、dtoのレスポンスとエラーを返す。
	Verify(urlParams map[string]string) *errs.AppError           //リクエストパラメータ一覧が入ったマップを受け取って、エラーを返す。
}

//このサービスは2つのドメイン層(リポジトリ)を持つ また、インターフェースの３つのメソッドを実装する。
type DefaultAuthService struct {
	repo              domain.AuthRepository //ログイン認証ドメイン
	rolePermissions   domain.RolePermissions //トークンの有効性確認ドメイン
}

func(s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError){
	var appErr *errs.AppError
	var login  *domain.Login //domain層のログイン構造体への参照

	if login, appErr = s.repo.FindBy(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}
	
	claims := login.ClaimsForAccessToken() //login構造体がメソッドを持ちます
	authToken := domain.NewAuthToken(claims) //token(Auth)構造体を生成します

	var accessToken string//authTokenから実際のアクセストークンを生成します
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil{
		return nil, appErr
	}

	return &dto.LoginResponse{
		AccessToken: accessToken,
	}, nil
}

//tokenの有効性を確認するサービスメソッド
func(s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {
	//まず、文字列のJWTtokenをJWTの構造体に変換する。
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		if jwtToken.Valid {
			//型キャスト
			claims := jwtToken.Claims.(*domain.AccessTokenClaims)
			if claims.IsUserRole() {
				if !claims.IsRequestVerifiedWithTokenClaims(urlParams) {
					return errs.NewAuthorizationError("リクエストはトークンクレイムに認められませでした。")
				}
			}
			isAuthorized := s.rolePermissions.IsAuthorizedFor(claims.Role, urlParams["routeName"])
			if !isAuthorized {
				return errs.NewAuthorizationError(fmt.Sprintf("%sは認められたユーザではありません", claims.Role))
			}
			return nil
		} else {
			return errs.NewAuthorizationError("このトークンは無効です!")
		}
	}
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error){
	//文字列からjwt型へトークンをパースする
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("トークンをパーシングしているときにエラーが発生しました。" + err.Error())
		return nil, err
	}
	return token, nil
}

func NewLoginService(repo domain.AuthRepository, permissions domain.RolePermissions) DefaultAuthService {
	return DefaultAuthService{
		repo, 
		permissions,
	}
}

