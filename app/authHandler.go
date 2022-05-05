package app

import(
	"encoding/json"
	"AUTH/dto"
	"AUTH/service"
	"github.com/natarisan/gop-libs/logger"
	"net/http"
)

type AuthHandler struct {
	service service.AuthService
}

func(h AuthHandler) Register(w http.ResponseWriter, r *http.Request){
	var registerRequest dto.RegisterRequest
	var loginRequest dto.LoginRequest
	if r.Method == "OPTIONS" {
		writeResponse(w, http.StatusOK, "")
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil{
		logger.Error("リクエストをデコードする際にエラーが発生しました。" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		loginRequest.Username = registerRequest.Username
		loginRequest.Password = registerRequest.Password
		appErr := h.service.Register(registerRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			token, appErr2 := h.service.Login(loginRequest) 
		    if appErr2 != nil { 
			writeResponse(w, appErr.Code, appErr.AsMessage())
		    } else {
			writeResponse(w, http.StatusOK, *token)
		    }
		}
	}
}

func(h AuthHandler) Login(w http.ResponseWriter, r *http.Request){
	var loginRequest dto.LoginRequest 
	if r.Method == "OPTIONS" {
		writeResponse(w, http.StatusOK, "")
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("リクエストをデコードする際にエラーが発生しました。" + err.Error())
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Login(loginRequest) 
		if appErr != nil { 
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

func (h AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] != "" {
		appErr := h.service.Verify(urlParams)
		if appErr != nil {
			writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("missing token"))
	}
}

func(h AuthHandler) Refresh(w http.ResponseWriter, r *http.Request){
	var refreshRequest dto.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil{
		logger.Error("リフレッシュトークンリクエストをデコードしている最中にエラーが発生しました")
		w.WriteHeader(http.StatusBadRequest)
	} else {
		token, appErr := h.service.Refresh(refreshRequest)
		if appErr != nil {
			writeResponse(w, appErr.Code, appErr.AsMessage())
		} else {
			writeResponse(w, http.StatusOK, *token)
		}
	}
}

//トークンが無効なときのレスポンスをマップで返す
func notAuthorizedResponse(msg string) map[int]bool {
	return map[int]bool{1000: false}
}

func authorizedResponse() map[int]bool {
	return map[int]bool{1000: true}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}){
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Header().Add("Access-Control-Allow-Headers", "*")
	w.Header().Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}