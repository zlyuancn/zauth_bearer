/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2019/9/25
   Description :
-------------------------------------------------
*/

package zauth_bearer

import (
    "github.com/dgrijalva/jwt-go"
    "time"
)

var (
    DefaultJWTAlgorithm     = jwt.SigningMethodHS512
    DefaultJWTAlgorithmName = "HS512"
)

type JWTData struct {
    jwt.StandardClaims
    User string `json:"user"`
}

func NewJWT(user string) *JWTData {
    return &JWTData{
        User: user,
    }
}

//获取jwt签名后的字符串
func (m *JWTData) GetString(secret []byte) (string, error) {
    m.IssuedAt = time.Now().Unix()
    token := jwt.NewWithClaims(DefaultJWTAlgorithm, m)
    tokenString, err := token.SignedString(secret)
    if err != nil {
        return "", err
    }
    return tokenString, nil
}

//设置jwt超时时间(纳秒)
func (m *JWTData) SetExpires(t time.Duration) {
    m.ExpiresAt = time.Now().Add(t).Unix()
}

//解析jwt数据
func (m *JWTData) ParserString(tokenString string, secret []byte) error {
    parser := &jwt.Parser{ValidMethods: []string{DefaultJWTAlgorithmName}}
    _, err := parser.ParseWithClaims(tokenString, m, func(token *jwt.Token) (interface{}, error) {
        return secret, nil
    })
    return err
}
