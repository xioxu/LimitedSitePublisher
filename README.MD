# LimitedSitePublisher
Sometimes, you want to publish an internal site to internet for some internal people, you may do not want your site can be accessed for everyone. So, it is the purpose of this project!

在有些场景下，我们需要将一些内部网站发布出去， 但是又不希望所有人都可以访问这个网站， 如果您有这样的需求，那么这个项目就是您所要找的！

## Usage
1.  Checkout the project to your server and publish 'npm install'  
 获取本项目代码，执行npm install,
1.  Set the DNS configuratoin or reverse proxy server(like nginx).  
 将您想要发布的公网域名配置好。
1.  Edit file 'site.conf', the following configuration means publish your internal site to a public address(ja.acb.net):  
 按照以下内容编辑"site.conf"
``` 
{
    "sites":{
        "ja.acb.net":"http://192.168.1.100:8888"
    },
    "port": 3000,
    "whitelistIp":[]
}
```
4. Make this project running(Strongly recommand use pm2).   
将本项目运行起来(建议使用pm2)。

## User Verefication
Just edit user.js and add your verification logic, e.g:  
通常情况下您需要定制登录逻辑， 编辑user.js， 完善逻辑即可， 记住只能修改 Promise内的方法体。

```
const request = require("request");

exports.verify = function (loginName, pwd) {
    return new Promise((resolve, reject) => {
        //Add your verification logic here.
        //return a object if the credential is valid, otherwise return null or false
	     request.ge("http://api.mystei.com/login",function(err,resp,body){
          if(err){
              reject(err);
           }else{
              resolve(body);
           }
        });
    })
};
```

*Notes*

Verify method must be a Promise method !

## Security
1. You can always use resolve(null) in verify method and specify whitelistIp to forbidden login.   
  *您可以通过使用resolve(null)并配合设置whitelistIp的方法来阻止用户登录，此时只有白名单ip可以访问。*
1. The ip address will be blocked onece login failed 5 times during 10 minutes.   
*如果您在10分钟内登录失败5次，ip将会被锁定！*