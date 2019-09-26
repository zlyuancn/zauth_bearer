/*
-------------------------------------------------
   Author :       Zhang Fan
   date：         2019/9/25
   Description :
-------------------------------------------------
*/

package zauth_bearer

type User struct {
    User string `json:"user" example:"username"` // 用户名
    Pwd  string `json:"pwd" example:"password"`  // 密码
}
