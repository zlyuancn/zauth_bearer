/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2019/9/25
   Description :
-------------------------------------------------
*/

package zauth_bearer

import "time"

type Option func(a *AuthBearer)

// 设置秘钥, 它影响token生成和解析
func WithSecret(secret []byte) Option {
    return func(a *AuthBearer) {
        a.secret = secret
    }
}

// 添加一个用户
func WithUser(name, pwd string) Option {
    return func(a *AuthBearer) {
        if name != "" && pwd != "" {
            a.userlist[name] = pwd
        }
    }
}

// 添加用户列表
func WithUserList(users map[string]string) Option {
    return func(a *AuthBearer) {
        if users != nil {
            for u, p := range users {
                if u != "" && p != "" {
                    a.userlist[u] = p
                }
            }
        }
    }
}

// 设置是否自动续期, 默认为true
func WithAutoKeepAlive(on bool) Option {
    return func(a *AuthBearer) {
        a.keepAlive = on
    }
}

// 设置存活时间, 单位为纳秒, 默认为600e9
func WithTTL(ttl time.Duration) Option {
    return func(a *AuthBearer) {
        a.ttl = ttl
    }
}

// 设置认证通过的自定义返回数据
func WithAuthOkFn(fn func(token string) string) Option {
    return func(a *AuthBearer) {
        a.authOkMsg = fn
    }
}

// 设置认证失败的自定义返回数据
func WithAuthErrFn(fn func(err error) string) Option {
    return func(a *AuthBearer) {
        a.authErrMsg = fn
    }
}

func authOkHandler(token string) string {
    return `{"code":200,"msg":"Authentication success"}`
}

func authErrHandler(err error) string {
    return `{"code":400,"msg":"Authentication failed"}`
}
