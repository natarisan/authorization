package app

import(
	"fmt"
	"AUTH/domain"
	"AUTH/service"
	"github.com/natarisan/gop-libs/logger"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"log"
	"net/http"
	"os"
	"time"
)

func Start(){//ハンドラ　サービス　ドメイン
	sanityCheck() //環境変数チェック
	router := mux.NewRouter()
	authRepository := domain.NewAuthRepository(getDbClient()) //ドメイン層のリポジトリを召喚し、そこにデータベースクライアントを渡している。
	ah := AuthHandler{service.NewLoginService(authRepository, domain.GetRolePermissions())} //ログインサービスを召喚している。
	//ハンドラの定義
	router.HandleFunc("/auth/login", ah.Login).Methods(http.MethodPost) //AuthHandlerの構造体はログインメソッドを持っている。
	router.HandleFunc("/auth/verify", ah.Verify).Methods(http.MethodGet) //同じく、Verifyメソッドを持っている。
	address := os.Getenv("SERVER_ADDRESS") //今回はlocalhost
	port    := os.Getenv("SERVER_PORT")    //今回は9876番
	logger.Info(fmt.Sprintf("認証サーバを起動しています。。。アドレス%s ポート%s", address, port))
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%s", address, port), router))
}

//データベースクライアントの作成
func getDbClient() *sqlx.DB{
	dbUser := os.Getenv("DB_USER")
	dbPasswd := os.Getenv("DB_PASSWD")
	dbAddr := os.Getenv("DB_ADDR") //localhost
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	dataSource := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPasswd, dbAddr, dbPort, dbName) //接続文字列
	client, err := sqlx.Open("mysql",dataSource) //データベースオープンしたクライアントを返す
	if err != nil{
		panic(err)
	}

	//dbクライアントに色々設定
	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)
	return client
}

func sanityCheck(){
	envProps := []string{
		"SERVER_ADDRESS",
		"SERVER_PORT",
		"DB_USER",
		"DB_PASSWD",
		"DB_ADDR",
		"DB_PORT",
		"DB_NAME",
	}

	for _, k := range envProps{
		if os.Getenv(k) == ""{
			logger.Error("おいおい、環境変数をちゃんと設定しろって。まったくもう。")
		}
	}
}