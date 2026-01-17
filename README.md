# Python Burp Suite Extension Template

This is a template for a Burp Suite Extension in Python. The template includes the most common components/interfaces.

Burp Suite requires Jython for all Python based extensions. Running the code through Jython and potentially loading additional Java libraries can sometimes cause issues. If you need to load a lot of libraries and/or have a complex logic etc, consider writing the extension in Java instead. 

Most use cases should be fine though and if you really don't like Java (don't blame you), there are ways to load Java libraries and use them with the Burp extension. JAR files can be imported in the code and then separately loaded in the Burp - Extension section by specifying the folder with the JAR libraries. (see TickTockEnum for an example)



Also felt like I should add a wee disclaimer... I'm not a programmer, so don't expect clean code and best practise coding. This is just a rough guide on how you can make a Burp extension, which is easier than you might think :)



## UX

The UX in the template includes a few different layouts, e.g.

- None (`BurpExtender` Class - `defineTabUX` function)
- Grid Bag Layout (`BurpExtender` Class - `dialogAction` function)
- Border Layout (`CustomTab` Class - `defineMessageEditorTabUX` function)



First to say, I'm pants at UX management, so for the main extension tab (ITab) I usually end up going with no layout and do absolute positioning and sizing. This is not ideal though as when you resize the Burp Suite window it's not responsive. Therefore if you know better or if it's a fairly simple UX, then suggest actually going for a layout. 

I found the Grid Bag Layout works well for Dialog windows (where you have a label and input field per row) or basic UX and the example for the Message Editor Tab was set to Border Layout and so went with that. 



## Template Interfaces

**IBurpExtender**

The most basic interface that all Burp extensions must implement. It provides a `registerExtenderCallbacks` method, which is the entry point for your extension. Here, it is possible to set up the extension, register listeners, and interact with Burp's API.



**IHttpListener**

Used to listen to and modify HTTP requests and responses as they pass through Burp Suite's tools (e.g., Proxy, Repeater). This interface provides the `processHttpMessage()` method to handle HTTP messages.



**IMessageEditorTabFactory, IMessageEditorTab and IMessageEditorController**

The combination is used to create custom tabs in HTTP message editors, such as those in the Proxy, Repeater, and Scanner tools.



**Message Handling**

The following interfaces can be used to get information about requests and responses:

- IHttpRequestResponse: inspect and manipulate requests and responses
- IHttpService: provides information like host, port, and protocol (HTTP/HTTPS) of a service
- IResponseInfo and IRequestInfo: analyse and extract information from HTTP requests and responses



**ITab**

Adds a custom tab to Burp Suite's UI. Implement this interface to define custom tabs, and register them using `addSuiteTab()`. It provides the `getTabCaption()` and `getUiComponent()` methods.



**IContextMenuFactory and IContextMenuInvocation**

Adds custom entries to Burp's context menus (right-click menus) within various tools. It can be defined what happens when users select these options.



**IBurpExtenderCallbacks**

This is the main interface through which your extension interacts with Burp Suite. It provides methods to register listeners, create message editors, send HTTP requests, issue alerts, and interact with Burp’s tools. Examples of methods:

- `registerHttpListener()`
- `registerScannerCheck()`
- `addSuiteTab()`
- `makeHttpRequest()`
- `createMessageEditor()`
- `issueAlert()`



**IExtensionHelpers**

Provides helper methods to perform common tasks, such as encoding and decoding data, analyzing HTTP requests and responses, and building HTTP requests. Example methods:

- `base64Encode()`
- `analyzeRequest()`
- `buildHttpRequest()`
- `urlEncode()`



## Other Interfaces

The template does not contain all possible interfaces, below are a few others of note:



**IProxyListener**

Allows the extension to intercept HTTP traffic in the Proxy tool. This interface provides the `processProxyMessage()` method, which gives control over requests and responses as they pass through the Burp Proxy.



**IScannerListener**

Allows the extension to listen for active or passive scan results. The `newScanIssue()` method notifies when Burp's Scanner finds a new issue.



**IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator and IIntruderPayloadProcessor**

Create custom payloads for Intruder.



**ISiteMap**

Allows the extension to retrieve and interact with the site map in Burp's Target tool. It represents the collection of all URLs and HTTP messages seen by Burp.



**ILoggingService**

Add custom logging to Burp Suite, so that the extension can write messages to Burp's log.