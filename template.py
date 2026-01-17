# Burp interfaces
from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorTabFactory, IMessageEditorTab, IMessageEditorController

# UX imports
from javax.swing import JMenuItem, JFileChooser, JPanel, JLabel, JTextArea, JButton, JScrollPane, JTextField, JOptionPane
from java.awt import GridBagLayout, GridBagConstraints, BorderLayout
from java.util import ArrayList

# other imports
import threading
import Queue as queue
import urlparse


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener, IMessageEditorTabFactory):		 
			
    # -----------------------------------------------------------------------------
    # MAIN FUNCTION
    # -----------------------------------------------------------------------------
    
    # required for IBurpExtender - initialises the Burp extension
    def registerExtenderCallbacks(self, callbacks):
        # Initial Burp Extension stuff (IBurpExtender)
        self._callbacks = callbacks
        callbacks.setExtensionName("Python Template")
        self._helpers = callbacks.getHelpers()

        # define threading lock (optional - only required when you do threading 
        # stuff, and even then it may depend whether this is necessary)
        self.lock = threading.Lock()

        # Create and register the Burp extention tab (ITab)
        self.defineTabUX()
        callbacks.addSuiteTab(self)

        # Register Context Menu (IContextMenuFactory)
        callbacks.registerContextMenuFactory(self)

        # Register a message editor tab (IMessageEditorTabFactory)
        callbacks.registerMessageEditorTabFactory(self)

        # Register HTTP listener interface (IHttpListener)
        callbacks.registerHttpListener(self)

    # -----------------------------------------------------------------------------
    # SUITE TAB INTERFACE
    # -----------------------------------------------------------------------------
    
    # required for ITab
    def getTabCaption(self):
        return "Burp Template"

    # required for ITab
    def getUiComponent(self):
        return self.panel

    # custom function to create the UX
    def defineTabUX(self):
        # UI
        self.panel = JPanel()
        self.panel.setLayout(None)

        # Define UX Elements and then set the return values
        UXElements = [
            { "type": "JLabel", "bounds": (10, 10, 80, 20), "text": "URL", "parameters": ( "Tooltip" ) },
            { "type": "JTextField", "bounds": (90, 10, 120, 20), "text": "https://www.pentestpartners.com/", "name": "textField_example" },
            { "type": "JTextArea", "bounds": (10, 50, 580, 300), "text": "", "name": "textArea_example" }
        ]

        for key, value in self.setupUX(UXElements).items():
            setattr(self, key, value)	

        # Add a scroll pane for the text area
        self.textAreaScrollPane = JScrollPane(self.textArea_example)
        self.textAreaScrollPane.setBounds(10, 50, 580, 300)
        self.panel.add(self.textAreaScrollPane)

        # Button examples
        self.button_threading = JButton("Threading", actionPerformed = self.threadingAction)
        self.button_threading.setBounds(240, 10, 80, 20)
        self.panel.add(self.button_threading)

        self.button_openFile = JButton("Open File", actionPerformed = self.openFileAction)
        self.button_openFile.setBounds(330, 10, 80, 20)
        self.panel.add(self.button_openFile)

        self.button_saveFile = JButton("Save File", actionPerformed = self.saveFileAction)
        self.button_saveFile.setBounds(420, 10, 80, 20)
        self.panel.add(self.button_saveFile)

        self.button_dialog = JButton("Dialog", actionPerformed = self.dialogAction)
        self.button_dialog.setBounds(510, 10, 80, 20)
        self.panel.add(self.button_dialog)

        self.button_clear = JButton("Clear", actionPerformed = self.basicAction)
        self.button_clear.setBounds(10, 360, 80, 20)
        self.panel.add(self.button_clear)

    # custom function to create the UX
    def setupUX(self, elements):
        return_refs = {}
        return_types = [ "JTextField", "JTextArea" ]
        for element in elements:
            newElement = globals()[element["type"]]()
            newElement.setBounds(element["bounds"][0], element["bounds"][1], element["bounds"][2], element["bounds"][3])
            if "text" in element:
                newElement.setText(element["text"])
            if element["type"] == "JLabel":
                if "parameters" in element:
                    newElement.setToolTipText(element["parameters"][0])
            self.panel.add(newElement)
				
            if element["type"] in return_types:
                return_refs[element["name"]] = newElement
        return return_refs		

    # custom button action: action run within a thread. This is necessary when you want 
    # to send a request etc. as to not block the UX thread
    def threadingAction(self, event):
        # Use a Queue to save data from the thread. While in this basic example it's not really necessary, it's better to do if you are creating multiple threads.
        q = queue.Queue()

        # as an example just going to send two random request and wait for the response
        self.runThread(q, "about-us/")
        self.runThread(q, "contact-us/")

    # custom button action: example of how to open a file with JFileChooser
    def openFileAction(self, event):
        # Create a file chooser
        fileChooser = JFileChooser()
        result = fileChooser.showOpenDialog(self.panel)
        
        # If the user selects a file
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = fileChooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            # Check if the selected file is a .txt file
            if not file_path.endswith(".txt"):
                JOptionPane.showMessageDialog(None, "Please select a .txt file", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            try:
                # open file and save contents to text area
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.textArea_example.append("[OPEN FILE] User opened a file with the following content: \n" + content + "\n\n")
            except Exception as e:
                JOptionPane.showMessageDialog(None, "There was an error opening the file", "Error", JOptionPane.ERROR_MESSAGE)
                print("Exception details: \n" + str(e)) # output will be shown in the Burp - Extension section in the Output tab
                return

    # custom button action: example of how to save data to a file with JFileChooser
    def saveFileAction(self, event):
        # only allow user to save a file if there is text in the textArea
        if self.textArea_example.getText():
            file_chooser = JFileChooser()
            result = file_chooser.showSaveDialog(self.panel)

            if result == JFileChooser.APPROVE_OPTION:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()

                # Ensure the file has a .txt extension
                if not file_path.endswith(".txt"):
                    file_path += ".txt"

                # Data to be saved (modify this to suit your needs)
                data = self.textArea_example.getText()

                # Write the data to file
                with open(file_path, "w") as file:
                    file.write(data)

                self.textArea_example.append("[SAVE FILE] User saved output to file.\n\n")
        
        else:
            # else return a wee error message
            JOptionPane.showMessageDialog(None, "Nothing to save", "Error", JOptionPane.ERROR_MESSAGE)
            return

    # custom button action: example of how to open and work in a dialog
    def dialogAction(self, event):
        dialogPanel = JPanel(GridBagLayout())

        gbc = GridBagConstraints()
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets.set(5, 5, 5, 5)

        # UX elements
        nameField = JTextField(50)
        notesField = JTextField(50)

        nameLabel = JLabel("Name:")
        notesLabel = JLabel("Notes:")

        # Add elements to the grid
        gbc.gridx = 0
        gbc.gridy = 0
        dialogPanel.add(nameLabel, gbc)

        gbc.gridx = 1
        dialogPanel.add(nameField, gbc)

        gbc.gridx = 0
        gbc.gridy = 1
        dialogPanel.add(notesLabel, gbc)

        gbc.gridx = 1
        dialogPanel.add(notesField, gbc)

        dialog_title = "Example Dialog"

        # SHOW DIALOG
        choice = JOptionPane.showConfirmDialog(None, dialogPanel, dialog_title, JOptionPane.OK_CANCEL_OPTION)

        if choice == JOptionPane.OK_OPTION:
            name = nameField.getText()
            notes = notesField.getText()

            if not name or not notes:
                JOptionPane.showMessageDialog(None, "Please fill in all required fields.", "Error", JOptionPane.ERROR_MESSAGE)
                return

            else:
                # Process Data
                self.textArea_example.append("[DIALOG] User entered data in the dialog:\nName: " + name + "\nNotes: " + notes + "\n\n")

    # custom button action: super basic button action that will just clear the text area.
    def basicAction(self, event):
        self.textArea_example.setText("")

    # custom function for creating a thread and running a function in the background
    def runThread(self, q, reqParam):
        thread = threading.Thread(target=self.backgroundTask, args=(q, reqParam, self.onThreadComplete))
        thread.setDaemon(True)
        thread.start()

    # custom function to be run in the background
    def backgroundTask(self, q, reqParam, callback):
        if self.textField_example.getText():
            url = self.textField_example.getText() + reqParam
            
            try:
                parsed_url = urlparse.urlparse(url)

                # Create an HTTP service (host, port, protocol)
                http_service = self._helpers.buildHttpService(parsed_url.hostname, parsed_url.port or (443 if parsed_url.scheme == "https" else 80), parsed_url.scheme)
                
                # Build the HTTP request (GET request in this case)
                request = "GET " + parsed_url.path + " HTTP/1.1\r\nHost: " + parsed_url.hostname + "\r\nConnection: close\r\n\r\n"
                byte_request = self._helpers.stringToBytes(request)

                # Send the request and get the response
                response = self._callbacks.makeHttpRequest(http_service, byte_request)

            except Exception as e:
                print(str(e))
            
            if response:
                q.put({"url": url, "response": response})
                callback(q)
        else:
            JOptionPane.showMessageDialog(None, "Please enter a URL", "Error", JOptionPane.ERROR_MESSAGE)
            return

    # custom function which will be called when the thread is complete
    def onThreadComplete(self, q):
        response_details = q.get()

        response_info = self._helpers.analyzeResponse(response_details["response"].getResponse())
        response_status = response_info.getStatusCode()

        # set lock before updating UI element - this is just a basic example, this technically wouldn't need a lock...
        self.lock.acquire()
        self.textArea_example.append("[RESPONSE RECEIVED]\n" + response_details["url"] + ": " + str(response_status) + "\n\n")
        self.lock.release()

    # -----------------------------------------------------------------------------
    # HTTP LISTENER INTERFACE
    # -----------------------------------------------------------------------------

    # required for IHttpListener - this method is invoked when an HTTP request or response is processed.
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        #if message is a request and is sent by an extension
        if messageIsRequest and toolFlag == self._callbacks.TOOL_EXTENDER:

            # show the url
            request_info = self._helpers.analyzeRequest(messageInfo)
            self.lock.acquire()
            self.textArea_example.append("[HTTP LISTENER] A request was sent / intercepted: " + str(request_info.getUrl()) + "\n\n")
            self.lock.release()        

    # -----------------------------------------------------------------------------
    # CONTEXT MENU INTERFACE
    # -----------------------------------------------------------------------------

    # required for IContextMenuFactory - creates the context menu in Burp Suite
    def createMenuItems(self, invocation):
        menu_item = JMenuItem("Example", actionPerformed=lambda x: self.processContextMenuRequest(invocation))
        menu_list = ArrayList()
        menu_list.add(menu_item)
        return menu_list

    # custom function that defines what happens when a user selects the context menu
    def processContextMenuRequest(self, invocation):
        selected_messages = invocation.getSelectedMessages()

        # user can select more than one message, so make sure to check how many they are attempting to send to the extension
        if selected_messages:
            message_info = selected_messages[0]

            # for this example, just grabbing the first entry. 
            request_info = self._helpers.analyzeRequest(message_info)
            http_service = message_info.getHttpService()

            # from these you can get the following infos
            request_details_list = []
            request_details_list.append("Host: " + str(http_service.getHost()))
            request_details_list.append("Port: " + str(http_service.getPort()))
            request_details_list.append("Protocol: " + str(http_service.getProtocol()))
            request_details_list.append("Path: " + request_info.getUrl().getPath())
            
            # headers
            headers_list = request_info.getHeaders()

            # body
            request_bytes = message_info.getRequest()
            body_offset = request_info.getBodyOffset()
            body = request_bytes[body_offset:].tostring()

            self.textArea_example.append("[CONTEXT MENU] User sent request through context menu\n\n")
            self.textArea_example.append("Request details:\n" + "\n".join(request_details_list) + "\n\n")
            self.textArea_example.append("Headers:\n" + "\n".join(headers_list) + "\n\n")
            self.textArea_example.append("Body:\n" + body + "\n\n")

    # -----------------------------------------------------------------------------
    # MESSAGE EDITOR TAB - INSTANCE
    # -----------------------------------------------------------------------------

    # required for IMessageEditorTabFactory - called for each message editor 
    # (Repeater, Proxy, etc.) to add a new tab.
    def createNewInstance(self, controller, editable):
        # Create and return a new instance of the custom message editor tab
        return CustomTab(self, controller, editable, self._callbacks, self._helpers)

# -----------------------------------------------------------------------------
# MESSAGE EDITOR TAB - CLASS
# -----------------------------------------------------------------------------
class CustomTab(IMessageEditorTab, IMessageEditorController):
    
    # required to initialise the custom message editor tab. 
    def __init__(self, extender, controller, editable, callbacks, helpers):
        self._controller = controller
        self._editable = editable
        self._callbacks = callbacks
        self._helpers = helpers
        
        self.defineMessageEditorTabUX()
        
        # Editor to display the tab in Burp Suite
        self._txtInput = callbacks.createMessageEditor(self, editable)
    
    # custom function to create and add the UI
    def defineMessageEditorTabUX(self):
        # Create the UI for the custom tab
        self.panel = JPanel(BorderLayout())
        self.textArea = JTextArea(20, 50)
        scrollPane = JScrollPane(self.textArea)
        self.panel.add(scrollPane, BorderLayout.CENTER)

    # required - part of IMessageEditorTab
    def getTabCaption(self):
        return "Template Tab"
    
    # required - part of IMessageEditorTab
    def getUiComponent(self):
        return self.panel
    
    # required - part of IMessageEditorTab: decide if the tab should be 
    # enabled for this message
    def isEnabled(self, content, isRequest):
        # Return True to enable this tab for the message, or False to disable 
        # it. Here we enable the tab for all messages, but you can add custom logic.
        return True
    
    # required - part of IMessageEditorTab: handle the display of the message
    def setMessage(self, content, isRequest):
        # Display the HTTP message in the custom tab. This method is 
        # called every time the tab is selected for a message.
        
        if content:
            message_info = self._helpers.bytesToString(content)
            self.textArea.setText(message_info)
        else:
            self.textArea.setText("")
    
    # required - part of IMessageEditorTab: get message content from the tab
    def getMessage(self):
        # This method is used to return the modified message, if applicable. 
        # Here we are not modifying the message, so we return None.
        return None
    
    # required - part of IMessageEditorTab: indicate whether the message has been modified
    def isModified(self):
        # Since we are not editing the message in this tab, return False.
        return False
    
    # required - part of IMessageEditorTab: handle request/response focus
    def getSelectedData(self):
        # This method returns any selected data in the tab, which can 
        # be used for things like highlighting.
        return None