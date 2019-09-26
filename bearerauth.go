/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2019/9/25
   Description :
-------------------------------------------------
*/

package zauth_bearer

import (
    "fmt"
    "github.com/kataras/iris"
    "github.com/zlyuancn/zerrors"
    "strings"
    "time"
)

const (
    DefaultHeadersAuthField = "Authorization"
    DefaultTokenPrefix      = "Bearer "
)

var (
    DefaultSecret               = []byte("zauth-bearer_secret")
    DefaultTTL    time.Duration = 600e9
)

type AuthBearer struct {
    secret     []byte                  // 秘钥, 它影响jwt的token生成
    userlist   map[string]string       // 用户列表
    ttl        time.Duration           // 存活时间纳秒, 默认为600e9
    keepAlive  bool                    // 自动续期, 默认为true
    authOkMsg  func(token string) string // 通过认证后返回一个消息
    authErrMsg func(err error) string  // 认证失败后返回一个消息
}

func New(opts ...Option) *AuthBearer {
    a := &AuthBearer{
        secret:     DefaultSecret,
        userlist:   map[string]string{},
        ttl:        DefaultTTL,
        keepAlive:  true,
        authOkMsg:  authOkHandler,
        authErrMsg: authErrHandler,
    }

    for _, o := range opts {
        o(a)
    }
    return a
}

// 认证, 它返回一个iris的Handler
//
// 客户端需要传入一个 json 格式的 body 用于验证, 如: {"user":"username","pwd":"youpassword"}
// 一旦认证通过, 会生成一个认证信息头并返回给客户端, 如: Authorization: Bearer token
func (m *AuthBearer) Authentication() func(iris.Context) {
    return func(ctx iris.Context) {
        u := new(User)
        err := ctx.ReadJSON(u)
        if err != nil {
            msg := m.authErrMsg(zerrors.Wrap(err, "无法解析传入的认证数据"))
            _, _ = ctx.WriteString(msg)
            return
        }

        pwd, ok := m.userlist[u.User]
        if !ok || u.Pwd != pwd {
            msg := m.authErrMsg(zerrors.Wrap(err, "用户名或密码错误"))
            _, _ = ctx.WriteString(msg)
            return
        }

        o := NewJWT(u.User)
        o.SetExpires(m.ttl)
        jwt, err := o.GetString(m.secret)
        if err != nil {
            msg := m.authErrMsg(zerrors.Wrap(err, "无法创建认证数据"))
            _, _ = ctx.WriteString(msg)
            return
        }

        msg := m.authOkMsg(jwt)
        ctx.Header(DefaultHeadersAuthField, fmt.Sprintf("%s%s", DefaultTokenPrefix, jwt))
        _, _ = ctx.WriteString(msg)
        return
    }
}

// 鉴权, 它返回一个iris的中间件用于要求用户必须登录
//
// 客户端必须将鉴权信息放在 header 的 Authorization 字段中
// 如 Authorization: Bearer token
// 如果鉴权成功, 会生成一个新的认证信息头并返回给客户端, 如: Authorization: Bearer token
func (m *AuthBearer) MustAuth() func(iris.Context) {
    return func(ctx iris.Context) {
        authText := ctx.GetHeader("Authorization")
        if i := strings.Index(authText, DefaultTokenPrefix); i != 0 {
            msg := m.authErrMsg(zerrors.New("token协议错误"))
            _, _ = ctx.WriteString(msg)
            return
        }

        jwt := authText[len(DefaultTokenPrefix):]

        o := new(JWTData)
        err := o.ParserString(jwt, m.secret)
        if err != nil {
            msg := m.authErrMsg(zerrors.New("token鉴权失败"))
            _, _ = ctx.WriteString(msg)
            return
        }

        _, ok := m.userlist[o.User]
        if !ok {
            msg := m.authErrMsg(zerrors.Wrap(err, "用户不存在"))
            _, _ = ctx.WriteString(msg)
            return
        }

        if m.keepAlive {
            o.SetExpires(m.ttl)
        }

        jwt, err = o.GetString(m.secret)
        if err != nil {
            msg := m.authErrMsg(zerrors.Wrap(err, "无法创建新的认证数据"))
            _, _ = ctx.WriteString(msg)
            return
        }

        ctx.Header(DefaultHeadersAuthField, fmt.Sprintf("%s%s", DefaultTokenPrefix, jwt))
        ctx.Next()
    }
}
