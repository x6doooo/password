var fs = require('fs');
var crypto = require('crypto');

var defaultConfig = {
    // 随机生成密码的长度
    "pwMinLength": 4,
    // 随机密码的可用字符
    "pwBaseString": "2345617890",
    // md5加密保存密码的盐
    "saltPrefix": "あらがきゆい",
    "saltSuffix": "Hello,world!",
    // aes加密传输的key和iv
    "aeskey": "1a25893d00fd770830923ffdcd28a959069e918f3f66308cf5a31a1d20a233da",
    "aesiv": "b4fff0a7107f55a2a14cab9a7a47f784"
};

// class
var PasswordEncoder = function(config) {
    this.setConfig(config);
};

PasswordEncoder.prototype = {
    constructor: PasswordEncoder,
    setConfig: function(config) {
        this.config = config || defaultConfig;
        this.config.aeskey = new Buffer(this.config.aeskey, 'hex');
        this.config.aesiv = new Buffer(this.config.aesiv, 'hex');
    },
    // 生成随机密码
    getRandomPassword: function() {
        // 密码可用字符
        var pwBaseString = this.config.pwBaseString;
        var pwBaseStringLength = pwBaseString.length;

        // 密码最小长度
        var pwMinLength = this.config.pwMinLength;
        
        var temPassword = '';
        for (var i = 0; i < pwMinLength; i++) {
            temPassword += pwBaseString.charAt(~~(Math.random() * pwBaseStringLength));
        }
        return temPassword;
    },

    encrypt: function(password) {
        var cipher = crypto.createCipheriv('aes-256-cbc', this.config.aeskey, this.config.aesiv);
        var crypted = cipher.update(password,'utf8','base64');
        crypted += cipher.final('base64');
        return crypted;
    },

    decrypt: function(password) {
        var decipher = crypto.createDecipheriv('aes-256-cbc', this.config.aeskey, this.config.aesiv);
        var dec = decipher.update(password,'base64','utf8');
        dec += decipher.final('utf8');
        return dec;
    },
    // 加盐 -> MD5
    // 密码入库
    // 登录校验
    addSaltAndUseMD5: function(password) {
        password = this.config.saltPrefix + password + this.config.saltSuffix;
        password = new Buffer(password, 'utf8');
        return crypto.createHash('md5').update(password).digest('hex');
    }
};

module.exports = PasswordEncoder;

