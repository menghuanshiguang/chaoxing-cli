# Chaoxing CLI (超星学习通)

对超星学习通(chaoxing.com / xxt / 泛雅)接口逆向的命令行工具：登录 / 课程 / 章节 / 进度 / 任务点 / 思考讨论 / 刷课，一站式搞定。

## 功能

| 命令 | 说明 |
|------|------|
| `chaoxing login -u <手机号> -p <密码>` | 账号密码登录（AES 加密）|
| `chaoxing login -u <手机号> --code <验证码>` | 短信验证码登录 |
| `chaoxing login -q` | 学习通 APP 扫码登录（terminal ASCII 二维码）|
| `chaoxing status` | 查看登录状态 |
| `chaoxing whoami` | 查看当前登录用户信息 |
| `chaoxing logout` | 清除本地 cookie |
| `chaoxing courses` | 课程列表（含 courseId / clazzId / cpi / 教师 / 状态）|
| `chaoxing courses --json` | 同上，JSON 输出（含 status 字段）|
| `chaoxing courses --ended` | 只看已结课课程 |
| `chaoxing courses --status <词>` | 按状态过滤 |
| `chaoxing chapters -c <课>` | 列出一门课的章节及每章任务点数量 |
| `chaoxing progress -c <课>` | 单科刷课进度（已完成/总数 百分比）|
| `chaoxing progress -a` | 全部课程刷课进度 |
| `chaoxing jobs -c <课> [-p <章>]` | 章节任务点目录（视频/文档/答题等 + 完成状态）|
| `chaoxing jobs -c <课> --json` | 同上，JSON 输出（含 jobid/mid/objectId 等）|
| `chaoxing discuss -c <课> [-p <章>]` | 思考讨论话题列表（🟢已回复/🔴未回复 完成状态）|
| `chaoxing discuss-reply -c <课> -t <话题> --content <内容>` | 在思考讨论话题发表回复（匿名加 --anonymous）|
| `chaoxing discuss-replies -c <课> -t <话题>` | 查看话题回复列表 |
| `chaoxing discuss-delete -c <课> -t <话题> [-r <回复uuid>]` | 删除自己的回复（不指定 -r 自动列出我的回复）|
| `chaoxing study -c <课> [--chapter N] [--type video,document,read,work] [--speed 2]` | 刷课：自动完成视频/文档/阅读/答题任务 |
| `chaoxing study -c <课> --type document` | 只刷文档任务 |
| `chaoxing work -c <课> [--chapter N]` | 获取答题任务题目列表（含字体解密）|
| `chaoxing work-answer -c <课> -w <作业> --answers "1:A;2:B,C;3:true" [--random-fill]` | 指定答案提交答题 |

`-c` 参数支持课程序号 / courseId / 课程名模糊匹配；留空则交互选择。

> 课程状态：进行中 / 课程已结束(已结课)。已结课课程同样可查章节、进度；但**学习上报/讨论完成状态会被平台冻结(403)**，只能看不能刷。

登录凭证保存于 `~/.chaoxing/cookies.txt`。

## 依赖

```
pip install requests pyaes qrcode beautifulsoup4 lxml fonttools
# 终端 ASCII 二维码需 pyzbar
apk add zbar py3-pyzbar          # Alpine/iSH
```

## 项目结构

```
chaoxing.py              # 主程序 (全部命令)
cxlib/                   # 字体解密 (font_decoder + cxsecret_font, 去掉参考项目依赖的轻量版)
resource/                # 加密字体映射表 font_map_table.json
```

## 登录接口（2026 逆向）

均带 PC UA。

### ① 账号密码
`POST https://passport2.chaoxing.com/fanyalogin`
```
uname    = AES(手机号)
password = AES(密码)
fid      = -1
refer    = https%3A%2F%2Fi.chaoxing.com
t        = true
forbidotherlogin=0  validate=  doubleFactorLogin=0  independentId=0
```
AES: `key=iv=u2oh6Vu^HWe4_AES`, CBC, PKCS7 padding, base64 输出。

### ② 短信验证码
`POST https://passport2.chaoxing.com/fanyaloginbycode`
```
uname   = 手机号(明文)
verCode = urlencode( AES(验证码) )
fid     = -1
refer   = 同上
```

### ③ 学习通 APP 扫码
```
GET  passport2.chaoxing.com/login?fid=&newversion=true&refer=..   # 302 -> /mlogin
解析 /mlogin 页面 hidden: <input id=uuid value=..>  <input id=enc value=..>
GET  passport2.chaoxing.com/createqr?uuid=<uuid>&fid=-1           # 返回二维码 PNG
POST passport2.chaoxing.com/getauthstatus  body: enc=<enc>&uuid=<uuid>
      data.status==true -> 登录成功(随后 GET refer 补全 cookie)
      data.type==4      -> 已扫, 等手机确认
      data.type==6      -> 已取消
轮询间隔3s, 上限55次(~2.7min)
```
二维码内容: `https://passport2.chaoxing.com/toauthlogin?uuid=..&enc=..&type=0`

## 参考
- [SuperStar_R_Android](https://github.com/menghuanshiguang/SuperStar_R_Android) —— AES 加密与登录实现参考
