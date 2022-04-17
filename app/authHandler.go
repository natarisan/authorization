package app

import(
	"encoding/json"
	"AUTH/dto"
	"AUTH/service"
	"github.com/natarisan/gop-libs/logger"
	"net/http"
)

//このstructはサービスを持つ。認証サービス。
type AuthHandler struct {
	service service.AuthService
}

//ログインハンドラー レスポンスを返す。 リクエストの中に認証情報が含まれている。こいつはサービスを呼び出す。dtoのログインリクエストを投げる。
func(h AuthHandler) Login(w http.ResponseWriter, r *http.Request){
	var loginRequest dto.LoginRequest //dtoリクエスト
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil{//リクエストボディをdtoのリクエストに変換
		logger.Error("リクエストをデコードする際にエラーが発生しました。(handler)")
		w.WriteHeader(http.StatusBadRequest)//ヘッダーにバッドリクエストステータスを付与して返す
	} else {
		token, appErr := h.service.Login(loginRequest) //ちゃんとリクエストをdtoに変換できたら、認証サービスを呼び出す。
		if appErr != nil{ //dtoを認証サービスに投げてエラーが出たら
			writeResponse(w, appErr.Code, appErr.AsMessage())//エラーコードとメッセージを返す
		} else {
			writeResponse(w, http.StatusOK, *token)//OKステータスとトークンへの参照を返す
		}
	}
}

//リクエストしてきた人が有効なトークンを持っているか？をリクエストのたびに判定する。トークンをクエリパラメータの中に入れておく。
func(h AuthHandler) Verify(w http.ResponseWriter, r *http.Request){
	urlParams := make(map[string]string)//パラメータを格納するマップを作成

	for k := range r.URL.Query(){//キー一覧をURLから取得
		urlParams[k] = r.URL.Query().Get(k)//キーに対応する値を取り出して生成したマップに入れていく
	}

	if urlParams["token"] != "" {
		appErr := h.service.Verify(urlParams) //トークン確認サービスを呼び出す。そこにurlParams（クエリの一覧）を送る。
		if appErr != nil {
			writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		} else {
			writeResponse(w, http.StatusOK, authorizedResponse())
		}
	} else {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("トークンがないよ"))
	}
}

//トークンが無効なときのレスポンスをマップで返す
func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

//これはmapの項目が１個だけなので、boolean型を返す。
func authorizedResponse() map[string]bool {
	return map[string]bool{
		"isAuthorized": true,
	}
}

//レスポンスを加工する。ヘッダーをつけてステータスコードもつける dataをjsonエンコードする　レスポンス、ステータスコード、データ（なんでもいい）を引数とする。
func writeResponse(w http.ResponseWriter, code int, data interface{}){
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}