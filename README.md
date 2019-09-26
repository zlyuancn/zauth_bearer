
# zauth_bearer
> bearer 认证

## 获得zauth_bearer
` go get -u github.com/zlyuancn/zauth_bearer `

## 导入zauth_bearer
```go
import "github.com/zlyuancn/zauth_bearer"
```

## 实例

```go
    auth := zauth_bearer.New(
        zauth_bearer.WithSecret([]byte("your_secret")),
        zauth_bearer.WithUser("username", "password"),
    )

    app := iris.Default()
    
    // 此处路由用于用户登录
    app.Post("/admin/auth", auth.Authentication())

    // 此处所有路由必须鉴权后才能访问
    admin := app.Party("/admin", auth.MustAuth())
    {
        admin.Get("/me", func(ctx context.Context) {
            _, _ = ctx.WriteString("[get] /admin")
        })
        admin.Post("/me", func(ctx context.Context) {
            _, _ = ctx.WriteString("[post] /admin")
        })
    }

    _ = app.Run(iris.Addr(":8080"))
```

## 访问
```
// 登录
[POST] http://127.0.0.1:8080/admin/auth
  {
    "user": "username",
    "pwd": "password"
  }

// 鉴权访问
[Headers] Authorization: Bearer token
[GET] http://127.0.0.1:8080/admin/me
```

## 所有的选项
```
// 设置秘钥, 它影响token生成和解析
WithSecret(secret []byte)
// 添加一个用户
WithUser(name, pwd string)
// 添加用户列表
WithUserList(users map[string]string)
// 设置是否自动续期, 默认为true
WithAutoKeepAlive(on bool)
// 设置存活时间, 单位为纳秒, 默认为600e9
WithTTL(ttl time.Duration)
// 设置认证通过的自定义返回数据
WithAuthOkFn(fn func(token string) string)
// 设置认证失败的自定义返回数据
WithAuthErrFn(fn func(err error) string)
```