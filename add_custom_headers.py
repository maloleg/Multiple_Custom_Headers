from burp import IBurpExtender, IScanIssue, IScannerCheck, IContextMenuFactory, IContextMenuInvocation, ITab, IParameter, ISessionHandlingAction
from javax.swing import JMenuItem
from javax import swing
from javax.swing import JPanel, JButton, JList, JTable, table, JLabel, JScrollPane, JTextField, WindowConstants, GroupLayout, LayoutStyle, JFrame
from java.awt import BorderLayout
import java.util.ArrayList as ArrayList
import java.lang.String as String
from java.lang import Short
import thread


class Interface_structure:
    # self.label: JLabel
    # self.enable_btn: JButton
    # self.disable_btn: JButton
    # self.delete_btn: JButton
    # self.text_field: JTextField

    # def __init__(self, label='', enable_btn, disable_btn, delete_btn, text_field):
    #     self.label = label
    #     self.enable_btn = enable_btn
    #     self.delete_btn = delete_btn
    #     self.disable_btn = disable_btn
    #     self.text_field = text_field
     def __init__(self, text_field):
        self.text_field = text_field

class BurpExtender(IBurpExtender, ISessionHandlingAction, ITab):
    # implement IBurpExtender

    # set everything up

    def __init__(self):
        self.headers_units = []
        self.headers_strings = []

    def registerExtenderCallbacks(self, callbacks):

        # get helpers - not needed here.
        self._helpers = callbacks.getHelpers()

        # support for burp-exceptions
        try:
            sys.stdout = callbacks.getStdout()
        except:
            pass
        
        # set our extension name
        callbacks.setExtensionName("Multiple Custom Headers")
        
        # add the tab to Burp's UI
        callbacks.addSuiteTab(self)
        callbacks.registerSessionHandlingAction(self)

        return    

    def getActionName(self):
        return "Multiple Custom Headers"

    def getTabCaption(self):
        """Burp uses this method to obtain the caption that should appear on the
        custom tab when it is displayed. Returns a string with the tab name.
        """
        return "Multiple Custom Headers"
    
    def getUiComponent(self):
        panel = JPanel(BorderLayout())
        # # create buttons
        def btn_add_click(event):
            # header_unit = Interface_structure(label = JLabel("not used"), enable_btn = JButton("ENABLE", actionPerformed=btn_enable_click), 
            #     disable_btn = JButton("DISABLE", actionPerformed=btn_disable_click), delete_btn = JButton("DELETE", actionPerformed=btn_delete_click),
            #      text_field = JTextField(10))

            header_unit = Interface_structure(text_field = JTextField(10))
            # is_used = JLabel("not used")
            # header_unit.label.setBounds(20, 50+len(self.headers_units)*50, 100,30)
            # txt = JTextField(10)
            header_unit.text_field.setBounds(120, 50 + len(self.headers_units) * 50, 300, 30)
            # btn = JButton("ENABLE", actionPerformed=btn_enable_click)
            # header_unit.enable_btn.setBounds(420, 50 + len(self.headers_units) * 50, 100, 30)

            # header_unit.disable_btn.setBounds(520, 50 + len(self.headers_units) * 50, 100, 30)
            # btn_delete = JButton("DELETE", actionPerformed=btn_delete_click)
            # header_unit.delete_btn.setBounds(620, 50 + len(self.headers_units) * 50, 100, 30)
            # unset = JButton("DISABLE", actionPerformed=btn_disable_click)

            # panel.add(header_unit.label)
            panel.add(header_unit.text_field)
            # panel.add(header_unit.enable_btn)
            # panel.add(header_unit.delete_btn)
            # panel.add(header_unit.disable_btn)
            
            self.headers_units.append(header_unit)
            # self.labels_list.append(txt)
            # self.buttons_list.append(btn)
            
            panel.setVisible(True)
            panel.repaint()
            return

        def btn_delete_click(event):
            # print event
            if len(self.headers_units) > 0:
                header_unit = self.headers_units[-1]
                # panel.remove(header_unit.label)
                panel.remove(header_unit.text_field)
                # panel.remove(header_unit.enable_btn)
                # panel.remove(header_unit.delete_btn)
                # panel.remove(header_unit.disable_btn)
                self.headers_units.pop()
                panel.repaint()

        def btn_enable_click(event):
            # print event
            self.headers_strings = []
            for i in self.headers_units:
                self.headers_strings.append(i.text_field.getText())

        def btn_disable_click(event):
            print event

        panel.setLocation(100,100)
        panel.setSize(300,200)
        panel.setLayout(None)

        btn = JButton("ADD NEW HEADER", actionPerformed=btn_add_click)
        btn.setBounds(120,20,150,20)

        btn_delete = JButton("DELETE LAST", actionPerformed=btn_delete_click)
        btn_delete.setBounds(320,20,150,20)

        btn_set = JButton("SET HEADERS", actionPerformed=btn_enable_click)
        btn_set.setBounds(520,20,150,20)
        panel.add(btn)
        panel.add(btn_delete)
        panel.add(btn_set)
        panel.setVisible(True)

        return panel

    def performAction(self, currentRequest, macroItems): 
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        msgBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        print headers
        for i in self.headers_strings:
            replaced = False
            for j in range(len(headers)):
                if i.split()[0] in headers[j]:
                    headers[j] = i
                    replaced = True
                    break
            if not replaced:
                headers.add(i)
        message = self._helpers.buildHttpMessage(headers, msgBody)
        print self._helpers.bytesToString(message)
        currentRequest.setRequest(message)
        return

try:
    FixBurpExceptions()
except:
    pass