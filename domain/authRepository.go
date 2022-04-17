package domain

import(
	"database/sql"
	"github.com/natarisan/gop-libs/errs"
	"github.com/natarisan/gop-libs/logger"
	"github.com/jmoiron/sqlx"
)

//認証リポジトリ。３つのメソッドをもつインターフェース
type AuthRepository interface {
	FindBy(username string, password string)(*Login, *errs.AppError) //ユーザネームとパスワードをもとにそのユーザがいるかどうか
}

//sqlに接続するクライアントを持つ構造体
type AuthRepositoryDb struct {
	client *sqlx.DB
}

//DBから該当するユーザに対応するログイン構造体を返す
func(d AuthRepositoryDb) FindBy(username, password string) (*Login, *errs.AppError) {
	var login Login
	sqll := `SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'`
	sqlVerify := `SELECT username, u.customer_id, role, group_concat(a.account_id) as account_numbers FROM users u
				LEFT JOIN accounts a ON a.customer_id = u.customer_id
  				WHERE username = ? and password = ?
  				GROUP BY a.customer_id`
	_, err0 := d.client.Exec(sqll)
	if err0 != nil {
		logger.Error("データベースエラー" + err0.Error())
		return nil, errs.NewUnexpectedError("予期せぬデータベースエラー")
	}
	//sqlを発動してデータをゲットします
	err := d.client.Get(&login, sqlVerify, username, password)
	if err != nil {
		//該当行が見つからなかった場合
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("無効な認証情報です。")
		} else {
			logger.Error("ログイン認証中、データベース操作でエラーが発生しました。" + err.Error())
			return nil, errs.NewUnexpectedError("予期せぬデータベースエラー")
		}
	}
	return &login, nil
}

//sqlクライアントをnewする
func NewAuthRepository(client *sqlx.DB) AuthRepositoryDb {
	return AuthRepositoryDb{
		client,
	}
}