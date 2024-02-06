from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JButton, JScrollPane, JTextArea, JComboBox, JOptionPane
from java.awt import BorderLayout, Color

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Dynamic Header Setter")
        
        # UI components
        self.panel = JPanel()
        self.textArea = JTextArea(10, 30)  # TextArea for header input
        self.scrollPane = JScrollPane(self.textArea)
        self.saveHeaderButton = JButton("Save Headers", actionPerformed=self.saveHeaders)
        self.renameHeaderButton = JButton("Rename Headers", actionPerformed=self.renameHeaders)
        self.removeHeaderButton = JButton("Remove Headers", actionPerformed=self.removeHeaders)
        self.headerSelector = JComboBox(["Select a header set"])
        self.applyButton = JButton("ON", actionPerformed=self.toggleApplyButton)
        self.applyButton.setBackground(Color.BLUE)  # Set initial color to blue
        
        # Layout setup
        self.panel.setLayout(BorderLayout())
        self.panel.add(self.scrollPane, BorderLayout.CENTER)
        buttonsPanel = JPanel()
        buttonsPanel.add(self.saveHeaderButton)
        buttonsPanel.add(self.renameHeaderButton)
        buttonsPanel.add(self.removeHeaderButton)
        buttonsPanel.add(self.headerSelector)
        buttonsPanel.add(self.applyButton)
        self.panel.add(buttonsPanel, BorderLayout.SOUTH)
        
        # Register listeners and add tab
        self._callbacks.registerHttpListener(self)
        self._callbacks.addSuiteTab(self)
        
        # Storage for header configurations
        self.headerConfigurations = {}
        self.selectedHeaders = None
        self.applyButtonState = False  # Initial state is OFF

    def getTabCaption(self):
        return "Dynamic Headers"
    
    def getUiComponent(self):
        return self.panel

    def saveHeaders(self, event):
        headerSetName = JOptionPane.showInputDialog(self.panel, "Enter a name for this header set:")
        if headerSetName:
            headerText = self.textArea.getText().strip()
            if headerText:
                self.headerConfigurations[headerSetName] = headerText
                self.headerSelector.addItem(headerSetName)
                JOptionPane.showMessageDialog(self.panel, "Headers saved successfully under the name '{}'!".format(headerSetName))
            else:
                JOptionPane.showMessageDialog(self.panel, "No headers to save.", "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self.panel, "The header set name cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE)

    def renameHeaders(self, event):
        selectedHeaderSetName = self.headerSelector.getSelectedItem()
        if selectedHeaderSetName and selectedHeaderSetName != "Select a header set":
            newName = JOptionPane.showInputDialog(self.panel, "Enter the new name for the header set:")
            if newName and newName not in self.headerConfigurations:
                self.headerConfigurations[newName] = self.headerConfigurations.pop(selectedHeaderSetName)
                self.headerSelector.removeItem(selectedHeaderSetName)
                self.headerSelector.addItem(newName)
                self.headerSelector.setSelectedItem(newName)
                JOptionPane.showMessageDialog(self.panel, "Header set renamed successfully!")
            elif not newName:
                JOptionPane.showMessageDialog(self.panel, "The new header set name cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self.panel, "A header set with this name already exists.", "Error", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self.panel, "Please select a valid header set to rename.", "Error", JOptionPane.ERROR_MESSAGE)

    def removeHeaders(self, event):
        selectedHeaderSetName = self.headerSelector.getSelectedItem()
        if selectedHeaderSetName and selectedHeaderSetName != "Select a header set":
            del self.headerConfigurations[selectedHeaderSetName]
            self.headerSelector.removeItem(selectedHeaderSetName)
            self.textArea.setText("")
            JOptionPane.showMessageDialog(self.panel, "Selected header set removed successfully!")
        else:
            JOptionPane.showMessageDialog(self.panel, "Please select a valid header set to remove.", "Error", JOptionPane.ERROR_MESSAGE)

    def toggleApplyButton(self, event):
        self.applyButtonState = not self.applyButtonState  # Toggle the state
        if self.applyButtonState:
            self.applyButton.setText("ON")
            self.applyButton.setBackground(Color.BLUE)
        else:
            self.applyButton.setText("OFF")
            self.applyButton.setBackground(Color.WHITE)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest and self.applyButtonState:
            selectedHeaderSetName = self.headerSelector.getSelectedItem()
            if selectedHeaderSetName and selectedHeaderSetName != "Select a header set":
                self.selectedHeaders = self.headerConfigurations[selectedHeaderSetName]
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                headers = list(requestInfo.getHeaders())
                # Remove headers that will be replaced by the ones added by the user
                headers = [header for header in headers if not any(usrHeader.split(":")[0].strip() + ":" in header for usrHeader in self.selectedHeaders.split("\n"))]
                # Add the headers from the textarea
                headers.extend([h for h in self.selectedHeaders.split("\n") if h.strip() != ""])
                # Reconstruct the request with the new headers
                messageInfo.setRequest(self._helpers.buildHttpMessage(headers, messageInfo.getRequest()[requestInfo.getBodyOffset():]))
