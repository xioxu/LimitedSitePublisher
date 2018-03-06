const request = require("request");

exports.verify = function (loginName, pwd) {
    return new Promise((resolve, reject) => {
        //Add your verification logic here.
        //return a object if the credential is valid, otherwise return null or false
	     resolve({user:loginName})
    })
};