# sink-logger
Transparently log everything passed into known JavaScript sinks - Sink Logger extension for Burp.

### Description

Sink Logger is a Burp Suite Extension that allows to transparently monitor various JavaScript sinks. All data passed into the defined sinks is logged into the browser's console. This is done by injecting a custom [Proxy](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Proxy) initialization script into chosen HTTP responses and "proxyfing" all sinks.

![Logs](sink-logger.png?raw=true "Sink Logger Filtered")

### Technical details

The extension intercepts responses and does 2 major things:

- In case the response is HTML or JavaScript it injects a script initializing a custom Proxy.
```JS
var QF9iYXlvdG9w = QF9iYXlvdG9w || new Proxy({}, {
    set: function(target, key, value, receiver) {
        if (value != undefined && value !== "") {
            if ((value + "").startsWith("[object")) {
                try {
                    var svalue = JSON.stringify(value);
                } catch(error) {}
            }
            console.warn(`Sink log (${key}): ${svalue !== undefined ? svalue : value}`);
        }
        return Reflect.set(target, key, value, receiver);
    }
});
```
- It "proxyfies" all sinks. Currently 3 different sink types are supported: **.innerHTML**, **eval()** and **document.write()**.
```python
self.sinkPatterns = {
    r'\.innerHTML=': '.innerHTML=QF9iYXlvdG9w.innerHTML=',
    r'eval\(([^)])': r'eval(QF9iYXlvdG9w.eval=\1',
    r'document\.write\(([^)])': r'document.write(QF9iYXlvdG9w.write=\1'
}
```

"Proxyfing" a sink means to edit existing JavaScript so that every sink is preceded by an assignment to the proxy:

```JS
x.innerHTML=x.trim(); // becomes x.innerHTML=QF9iYXlvdG9w.innerHTML=x.trim();
document.write("string"); // becomes document.write(QF9iYXlvdG9w.write="string");
```

No sematic changes, no syntax errors (please report an issue if you find out otherwise).

### Remarks

- During the process CSP headers (and the `<meta>` tag) as well as SRI checks are stripped. **This puts you at risk when surfing the web**.
- Websites may break. The aim is to be completely transparent, in some cases, however, the modifications may result in invalid JavaScript syntax or otherwise break web-apps. Please consider reporting an issue if you encounter such behavior.
