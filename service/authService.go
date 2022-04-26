package service

import(
	"fmt"
	"AUTH/domain"
	"AUTH/dto"
	"github.com/natarisan/gop-libs/errs"
	"github.com/natarisan/gop-libs/logger"
	"github.com/dgrijalva/jwt-go"
)

type AuthService interface {
	Login(dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) 
	Verify(urlParams map[string]string) *errs.AppError          
	Refresh(request dto.RefreshTokenRequest)(*dto.LoginResponse, *errs.AppError)
}

type DefaultAuthService struct {
	repo              domain.AuthRepository 
	rolePermissions   domain.RolePermissions 
}

func(s DefaultAuthService) Refresh(request dto.RefreshTokenRequest)(*dto.LoginResponse, *errs.AppError){
	if vErr := request.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			var appErr *errs.AppError
			if appErr = s.repo.RefreshTokenExists(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(request.RefreshToken); appErr != nil {
				return nil, appErr
			}
			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("無効なトークン")
	}
	return nil, errs.NewAuthenticationError("有効期限が切れるまで新しいリフレッシュトークンを作成することはできません")
}

func(s DefaultAuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError){
	var appErr *errs.AppError
	var login  *domain.Login

	if login, appErr = s.repo.FindBy(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}
	
	claims := login.ClaimsForAccessToken() 
	authToken := domain.NewAuthToken(claims)

	var accessToken, refreshToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil{
		return nil, appErr
	}

	if refreshToken, appErr = s.repo.GenerateAndSaveRefreshTokenToStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{
		AccessToken: accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func(s DefaultAuthService) Verify(urlParams map[string]string) *errs.AppError {
	if jwtToken, err := jwtTokenFromString(urlParams["token"]); err != nil {
		return errs.NewAuthorizationError(err.Error())
	} else {
		if jwtToken.Valid {
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

