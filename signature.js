//frida WeChat.exe -l
var WeChatWin = Process.findModuleByName('WeChatWin.dll');
var WeChatAppHost = Process.findModuleByName('WeChatAppHost.dll');
if (WeChatWin && WeChatAppHost) {
    var hookAddress = WeChatWin.base.add('0x8277F');
    Interceptor.attach(hookAddress, {
        onEnter: function (args) {
            var esi = this.context.esi;
            var r = ptr(esi).readCString();
            if (r.indexOf("\"iv\"") != -1) {
                send({'signature': '{"rawData":' + r.substring(r.indexOf("\"{"))});
            }
            // send(r);
        }
    })
}