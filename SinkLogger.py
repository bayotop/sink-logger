from burp import IBurpExtender, IProxyListener, ITab

from java.awt import FlowLayout 
from java.awt.event import ItemEvent, ItemListener
from java.io import PrintWriter
from javax.swing import JCheckBox, JPanel

import re

class BurpExtender(IBurpExtender, IProxyListener, ITab):
    
    # Implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # Keep some useful references
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set the extension name
        callbacks.setExtensionName("Sink Logger")
        
        # Obtain the output stream
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # Register as a Proxy listener
        callbacks.registerProxyListener(self)

        # Initialize and register UI
        self.initUserInterface()
        callbacks.addSuiteTab(self)

        # Extension specific stuff
        self.loggingEnabled = False

        self.scriptContentTypes = ["javascript", "ecmascript", "jscript", "json"]
        self.excludedContentTypes = ['text/css', "image/", "text/plain", "application/x-octet-stream"]
        self.commonHijackingProtections = ["for (;;);", ")]}'", "{} &&", "while(1);" ]

        # In Chrome console.warn shows an extremely useful stack trace and it's hidden by default so the output is not a mess (i.e. console.trace())
        # Minified version of this script is injected into responses
        """
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
        """
        self.proxyInitialization = "var QF9iYXlvdG9w=QF9iYXlvdG9w||new Proxy({},{set:function set(a,b,c,d){if(c!=void 0&&\"\"!==c){if((c+\"\").startsWith(\"[object\"))try{var e=JSON.stringify(c)}catch(f){}console.warn(\"Sink log (\"+b+\"): \"+(e===void 0?c:e))}return Reflect.set(a,b,c,d)}});"
        self.proxyInitializationHTML = "<script>%s</script>" % self.proxyInitialization

        # pattern: replacement passed into re.sub()
        self.sinkPatterns = {
            r'\.innerHTML(|[ ])=([^=])': r'.innerHTML=QF9iYXlvdG9w.innerHTML=\2',
            r'eval\(([^)])': r'eval(QF9iYXlvdG9w.eval=\1',
            r'document\.write\(([^)])': r'document.write(QF9iYXlvdG9w.write=\1',
            # r'\$\(([^)])': r'$(QF9iYXlvdG9w.jQuery=\1'
        }

        # CSP / SRI
        self.metaHeaderPattern = re.compile("<meta.*Content-Security-Policy.*>", flags=re.MULTILINE|re.IGNORECASE)
        self.integrityAttributesPattern = re.compile("integrity(.{1,3})sha", flags=re.IGNORECASE)

        self._stdout.println("GitHub: https://github.com/bayotop/sink-logger")
        self._stdout.println("Contact: https://twitter.com/_bayotop")
        self._stdout.println("")
        self._stdout.println("Successfully initialized Sink Logger...")


    # Implement IProxyListener
    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest or not self.loggingEnabled:
            return

        try:
            response = message.getMessageInfo().getResponse()
        except:
            return

        # Process the response and inject the proxy initialization script if HTML / JS
        responseHeaders = self._helpers.analyzeResponse(response).getHeaders()
        responseBody = self.processResponse(response)
        if not responseBody:
            return

        # Get rid of CSP and SRI to ensure that the injected script executes
        editedResponseHeaders = [x for x in responseHeaders if not "content-security-policy" in x.lower()] 
        responseBody = self.integrityAttributesPattern.sub(r'integrityx\1sha', responseBody)           
        responseBody = self.metaHeaderPattern.sub("", responseBody)
        
        # "Proxify" sinks in response
        for key,value in self.sinkPatterns.items():
            responseBody = re.sub(key, value, responseBody)

        editedResponse = self._helpers.buildHttpMessage(editedResponseHeaders, responseBody)
        message.getMessageInfo().setResponse(editedResponse)

        # Let users review the response for modification in UI
        message.setInterceptAction(message.ACTION_FOLLOW_RULES)

    def processResponse(self, response):      
        analyzedResponse = self._helpers.analyzeResponse(response)
        responseBody = response[analyzedResponse.getBodyOffset():]
        if not responseBody or self.checkContentType(analyzedResponse, self.excludedContentTypes):
            return False

        responsePeek = responseBody[0:100].tostring().lstrip()
        mimeType = analyzedResponse.getStatedMimeType().split(';')[0]
        inferredMimeType = analyzedResponse.getInferredMimeType().split(';')[0]

        # Inject script into HTML and JS (and exclude JSON)
        if responsePeek.lower().startswith("<html") or responsePeek.lower().startswith("<!doctype html"):
            return self.processHtml(responseBody.tostring())
        elif (all(x not in responsePeek for x in self.commonHijackingProtections) and
             (responsePeek[0] not in ["{","["]) and 
             ("script" in mimeType or "script" in inferredMimeType or self.checkContentType(analyzedResponse, self.scriptContentTypes))):
            return self.proxyInitialization + responseBody
        else:
            # All unrecognized responses will be "proxified"
            return responseBody

    def checkContentType(self, analyzedResponse, patterns):
        headers = analyzedResponse.getHeaders()
        contentTypeHeaders = [x for x in headers if "content-type:" in x.lower()]
        for cth in contentTypeHeaders:
            if any(c in cth.lower() for c in patterns):
                return True
        return False

    def processHtml(self, response):
        # Browsers do weird stuff if a script precedes the doctype / root html element
        if "<head>" in response:
            return response.replace("<head>", "<head>" + self.proxyInitializationHTML, 1)
        if "</title>" in response:
            return response.replace("</title>", "</title>" + self.proxyInitializationHTML, 1)
        if "<body>" in response:
            return response.replace("<body>", "<body>" + self.proxyInitializationHTML, 1)          
        return self.proxyInitializationHTML + response


    # Implement ITab
    def getTabCaption(self):
        return "Sink Logger"
    
    def getUiComponent(self):
        return self.configurationPanel

    def initUserInterface(self):
        class TriggerLoggingListener(ItemListener):
            def __init__(self, extender):
                self.extender = extender

            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    self.extender.loggingEnabled = True
                else:
                    self.extender.loggingEnabled = False

        loggingTrigger = JCheckBox("Enable logging (clearing browser cache might be needed to reflect the change)")
        loggingTrigger.addItemListener(TriggerLoggingListener(self))

        self.configurationPanel = JPanel()
        self.configurationPanel.setLayout(FlowLayout(FlowLayout.LEFT))
        self.configurationPanel.add(loggingTrigger)
