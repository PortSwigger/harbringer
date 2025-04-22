from burp import IBurpExtender, ITab, IHttpRequestResponse, IHttpService
from javax.swing import JPanel, JButton, JScrollPane, JTable, JTextField, JLabel, JOptionPane, JFileChooser, ListSelectionModel
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout, FlowLayout, Dimension
from java.net import URL
from java.io import File
import java
import javax
import json
import traceback
import base64

# Custom implementation of IHttpRequestResponse
class HttpRequestResponse(IHttpRequestResponse):
    def __init__(self, host, port, protocol, request, response):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._request = request
        self._response = response
        self._comment = None
        self._highlight = None

    def getComment(self):
        return self._comment

    def getHighlight(self):
        return self._highlight

    def getHttpService(self):
        return HttpService(self._host, self._port, self._protocol)

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, comment):
        self._comment = comment

    def setHighlight(self, color):
        self._highlight = color

    def setHttpService(self, httpService):
        self._host = httpService.getHost()
        self._port = httpService.getPort()
        self._protocol = httpService.getProtocol()

    def setRequest(self, message):
        self._request = message

    def setResponse(self, message):
        self._response = message

# Custom implementation of IHttpService
class HttpService(IHttpService):
    def __init__(self, host, port, protocol):
        self._host = host
        self._port = port
        self._protocol = protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol

    def __str__(self):
        return "%s://%s:%d" % (self._protocol, self._host, self._port)

# Table model for HAR entries
class HarTableModel(AbstractTableModel):
    def __init__(self, entries):
        self.entries = entries
        self.columnNames = ["#", "Method", "URL", "Status", "Length", "MIME Type"]
#        self.columnClasses = [int, str, str, int, str, int, int]  # Make sure the first column is int type


    def getColumnCount(self):
        return len(self.columnNames)

    def getRowCount(self):
        return len(self.entries)

    def getColumnName(self, column):
        return self.columnNames[column]
    
    def getColumnClass(self, column):
        if column == 0:  # Request Number column
            return java.lang.Integer
        elif column == 4:  # Length column
            return java.lang.Integer
        else:
            return java.lang.String


    def getValueAt(self, row, column):
        entry = self.entries[row]
        request = entry.get('request', {})
        response = entry.get('response', {})

        if column == 0: # Request Number
            return row + 1
        elif column == 1:
            return request.get('method', '')
        elif column == 2:
            return request.get('url', '')
        elif column == 3:
            return response.get('status', 0)
        elif column == 4:
            content = response.get('content', {})
            return content.get('size', 0)
        elif column == 5:
            content = response.get('content', {})
            return content.get('mimeType', '')
        return ""

    def clearData(self):
        self.entries = []
        self.fireTableDataChanged()  # This notifies the table that data has changed


# Main extension class
class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = callbacks.getStdout()

        callbacks.setExtensionName("HARbringer - HAR Importer")

        # Initialize UI
        self.initUI()

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        self.log("[HARbringer] Extension loaded successfully!")

    def initUI(self):
        self.panel = JPanel(BorderLayout())

        # Top panel for file selection
        topPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        self.filePathField = JTextField(30)
        self.filePathField.setEditable(False)

        browseButton = JButton("Browse", actionPerformed=self.browse_file)
        self.loadButton = JButton("Load HAR", actionPerformed=self.load_har)
        self.clearButton = JButton("Clear", actionPerformed=self.clear_table)

        
        topPanel.add(JLabel("HAR File:"))
        topPanel.add(self.filePathField)
        topPanel.add(browseButton)
        topPanel.add(self.loadButton)
        topPanel.add(self.clearButton)

        self.panel.add(topPanel, BorderLayout.NORTH)

        # Table for HAR entries
        self.entries = []
        self.tableModel = HarTableModel(self.entries)
        self.table = JTable(self.tableModel)
        self.table.setAutoCreateRowSorter(True)

        # Single selection mode
        self.table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION)


        scrollPane = JScrollPane(self.table)
        scrollPane.setPreferredSize(Dimension(800, 400))

        self.panel.add(scrollPane, BorderLayout.CENTER)

        # set column widths
        self.table.getColumnModel().getColumn(0).setPreferredWidth(30)  # Request Number
        self.table.getColumnModel().getColumn(1).setPreferredWidth(50)  # Method
        self.table.getColumnModel().getColumn(2).setPreferredWidth(800)  # URL
        self.table.getColumnModel().getColumn(3).setPreferredWidth(50)  # Status
        self.table.getColumnModel().getColumn(4).setPreferredWidth(50)  # Length
        self.table.getColumnModel().getColumn(5).setPreferredWidth(150)  # MIME Type


        # Set maximum widths for non-URL columns
        self.table.getColumnModel().getColumn(0).setMaxWidth(30)  # Request Number
        self.table.getColumnModel().getColumn(1).setMaxWidth(50)  # Method
        self.table.getColumnModel().getColumn(3).setMaxWidth(50)  # Status
        self.table.getColumnModel().getColumn(4).setMaxWidth(50)  # Length
        self.table.getColumnModel().getColumn(5).setMaxWidth(150)  # MIME Type




        # Bottom panel for actions
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        self.sendToHistoryButton = JButton("Send to Site Map", actionPerformed=self.send_selected_to_http_history)
        self.importAllButton = JButton("Import All to Site Map", actionPerformed=self.import_all_to_sitemap)

        buttonPanel.add(self.sendToHistoryButton)
        buttonPanel.add(self.importAllButton)

        self.panel.add(buttonPanel, BorderLayout.SOUTH)

        # button state
        self.sendToHistoryButton.setEnabled(False)
        self.importAllButton.setEnabled(False)
        self.clearButton.setEnabled(False)
        self.loadButton.setEnabled(False)

    def getTabCaption(self):
        return "HARbringer"

    def getUiComponent(self):
        return self.panel

    def log(self, message):
        print(message)

    def browse_file(self, event):
        fileChooser = JFileChooser()
        result = fileChooser.showOpenDialog(self.panel)

        if result == JFileChooser.APPROVE_OPTION:
            selectedFile = fileChooser.getSelectedFile()
            self.filePathField.setText(selectedFile.getAbsolutePath())
            self.loadButton.setEnabled(True)

    def load_har(self, event):
        filePath = self.filePathField.getText()

        if not filePath:
            JOptionPane.showMessageDialog(None, "Please select a HAR file.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        try:
            self.log("[HARbringer] Loading HAR file: %s" % filePath)

            with open(filePath, 'r') as f:
                har_data = json.load(f)

            har_log = har_data.get('log', {})
            entries = har_log.get('entries', [])

            self.log("[HARbringer] Found %d entries in HAR file" % len(entries))

            self.entries = entries
            self.tableModel = HarTableModel(self.entries)
            self.table.setModel(self.tableModel)

            # set column widths
            self.table.getColumnModel().getColumn(0).setPreferredWidth(30)  # Request Number
            self.table.getColumnModel().getColumn(1).setPreferredWidth(50)  # Method
            self.table.getColumnModel().getColumn(2).setPreferredWidth(800)  # URL
            self.table.getColumnModel().getColumn(3).setPreferredWidth(50)  # Status
            self.table.getColumnModel().getColumn(4).setPreferredWidth(50)  # Length
            self.table.getColumnModel().getColumn(5).setPreferredWidth(150)  # MIME Type


            # Set maximum widths for non-URL columns
            self.table.getColumnModel().getColumn(0).setMaxWidth(30)  # Request Number
            self.table.getColumnModel().getColumn(1).setMaxWidth(50)  # Method
            self.table.getColumnModel().getColumn(3).setMaxWidth(50)  # Status
            self.table.getColumnModel().getColumn(4).setMaxWidth(50)  # Length
            self.table.getColumnModel().getColumn(5).setMaxWidth(150)  # MIME Type

            # enable buttons
            self.sendToHistoryButton.setEnabled(True)
            self.importAllButton.setEnabled(True)
            self.clearButton.setEnabled(True)



            self.log("[HARbringer] Imported %d entries successfully" % len(entries))
            JOptionPane.showMessageDialog(None, "Imported %d entries successfully." % len(entries), "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self.log("[HARbringer] Error loading HAR file: %s" % str(e))
            traceback.print_exc(file=self._stdout)
            JOptionPane.showMessageDialog(None, "Error: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def send_selected_to_http_history(self, event):
        row = self.table.getSelectedRow()

        if row < 0:
            JOptionPane.showMessageDialog(None, "No row selected.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        model_row = self.table.convertRowIndexToModel(row)

        if model_row >= len(self.entries):
            JOptionPane.showMessageDialog(None, "Invalid selection.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        entry = self.entries[model_row]

        try:
            # Extract request details
            request = entry.get('request', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')
            req_headers = request.get('headers', [])
            post_data = request.get('postData', {})
            req_body = post_data.get('text', '')

            # Check if body is base64 encoded
            if post_data.get('encoding') == 'base64' and req_body:
                req_body = base64.b64decode(req_body)

            # Extract response details
            response = entry.get('response', {})
            status = response.get('status', 200)
            status_text = response.get('statusText', 'OK')
            resp_headers = response.get('headers', [])
            resp_content = response.get('content', {})
            resp_body = resp_content.get('text', '')

            # Check if body is base64 encoded
            if resp_content.get('encoding') == 'base64' and resp_body:
                resp_body = base64.b64decode(resp_body)

            # Parse URL
            url_obj = URL(url)
            protocol = url_obj.getProtocol()
            host = url_obj.getHost()
            port = url_obj.getPort()
            if port == -1:
                port = 443 if protocol.lower() == 'https' else 80

            # Build request
            path = url_obj.getPath()
            query = url_obj.getQuery()
            if query:
                path = path + "?" + query

            request_line = "%s %s HTTP/1.1" % (method, path)

            header_lines = []
            has_host = False
            for h in req_headers:
                name = h.get('name', '')
                value = h.get('value', '')
                if name.lower() == 'host':
                    has_host = True
                header_lines.append("%s: %s" % (name, value))

            if not has_host:
                header_lines.insert(0, "Host: %s" % host)

            raw_request = request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
            if req_body:
                raw_request += req_body

            # Build response
            response_line = "HTTP/1.1 %d %s" % (status, status_text)

            resp_header_lines = []
            for h in resp_headers:
                name = h.get('name', '')
                value = h.get('value', '')
                resp_header_lines.append("%s: %s" % (name, value))

            raw_response = response_line + "\r\n" + "\r\n".join(resp_header_lines) + "\r\n\r\n"
            if resp_body:
                raw_response += resp_body

            # Convert to bytes
            request_bytes = self._helpers.stringToBytes(raw_request)
            response_bytes = self._helpers.stringToBytes(raw_response)

            self.log("[HARbringer] Request bytes length: %d" % len(request_bytes))
            self.log("[HARbringer] Response bytes length: %d" % len(response_bytes))
            self.log("[HARbringer] HTTP Service: %s:%d (%s)" % (host, port, protocol))

            # Create custom IHttpRequestResponse object
            req_resp = HttpRequestResponse(host, port, protocol, request_bytes, response_bytes)

            # Add to site map
            self._callbacks.addToSiteMap(req_resp)

            self.log("[HARbringer] Added to site map: %s %s" % (method, url))
            JOptionPane.showMessageDialog(None, "Entry added to site map.", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self.log("[HARbringer] Error adding to site map: %s" % str(e))
            traceback.print_exc(file=self._stdout)
            JOptionPane.showMessageDialog(None, "Error: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def clear_table(self, event):
        self.tableModel.clearData()
        self.entries = []
        # Disable buttons after clearing
        self.sendToHistoryButton.setEnabled(False)
        self.importAllButton.setEnabled(False)
        self.clearButton.setEnabled(False)


    def import_all_to_sitemap(self, event):
        if not self.entries:
            JOptionPane.showMessageDialog(None, "No entries to import.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        try:
            count = 0
            errors = 0

            for entry in self.entries:
                try:
                    # Extract request details
                    request = entry.get('request', {})
                    url = request.get('url', '')
                    method = request.get('method', 'GET')
                    req_headers = request.get('headers', [])
                    post_data = request.get('postData', {})
                    req_body = post_data.get('text', '')

                    # Check if body is base64 encoded
                    if post_data.get('encoding') == 'base64' and req_body:
                        req_body = base64.b64decode(req_body)

                    # Extract response details
                    response = entry.get('response', {})
                    status = response.get('status', 200)
                    status_text = response.get('statusText', 'OK')
                    resp_headers = response.get('headers', [])
                    resp_content = response.get('content', {})
                    resp_body = resp_content.get('text', '')

                    # Check if body is base64 encoded
                    if resp_content.get('encoding') == 'base64' and resp_body:
                        resp_body = base64.b64decode(resp_body)

                    # Parse URL
                    url_obj = URL(url)
                    protocol = url_obj.getProtocol()
                    host = url_obj.getHost()
                    port = url_obj.getPort()
                    if port == -1:
                        port = 443 if protocol.lower() == 'https' else 80

                    # Build request
                    path = url_obj.getPath()
                    query = url_obj.getQuery()
                    if query:
                        path = path + "?" + query

                    request_line = "%s %s HTTP/1.1" % (method, path)

                    header_lines = []
                    has_host = False
                    for h in req_headers:
                        name = h.get('name', '')
                        value = h.get('value', '')
                        if name.lower() == 'host':
                            has_host = True
                        header_lines.append("%s: %s" % (name, value))

                    if not has_host:
                        header_lines.insert(0, "Host: %s" % host)

                    raw_request = request_line + "\r\n" + "\r\n".join(header_lines) + "\r\n\r\n"
                    if req_body:
                        raw_request += req_body

                    # Build response
                    response_line = "HTTP/1.1 %d %s" % (status, status_text)

                    resp_header_lines = []
                    for h in resp_headers:
                        name = h.get('name', '')
                        value = h.get('value', '')
                        resp_header_lines.append("%s: %s" % (name, value))

                    raw_response = response_line + "\r\n" + "\r\n".join(resp_header_lines) + "\r\n\r\n"
# Get the encoding from the Content-Type header if available
                    content_type = resp_content.get('mimeType', '')
                    encoding = 'utf-8'  # Default encoding
                    if content_type and 'charset=' in content_type:
                        try:
                            # Extract encoding from content type
                            encoding = content_type.split('charset=')[1].split(';')[0].strip()
                        except IndexError:
                            pass  # No charset specified, use default

                    # Handle the response body encoding
                    if isinstance(resp_body, bytes):
                        try:
                            resp_body = resp_body.decode(encoding)
                        except UnicodeDecodeError:
                            # Fallback to latin-1 which can handle any byte value
                            resp_body = resp_body.decode('latin-1')
                    raw_response += resp_body
                    request_bytes = self._helpers.stringToBytes(raw_request)
                    response_bytes = self._helpers.stringToBytes(raw_response)

                    # Create custom IHttpRequestResponse object
                    req_resp = HttpRequestResponse(host, port, protocol, request_bytes, response_bytes)

                    # Add to site map
                    self._callbacks.addToSiteMap(req_resp)

                    count += 1
                    if count % 10 == 0:
                        self.log("[HARbringer] Imported %d entries so far..." % count)
                except Exception as entry_error:
                    self.log("[HARbringer] Error importing entry: %s" % str(entry_error))
                    traceback.print_exc(file=self._stdout)
                    errors += 1
                    continue

            self.log("[HARbringer] Import complete. Imported %d entries with %d errors." % (count, errors))
            JOptionPane.showMessageDialog(None, "Imported %d entries with %d errors." % (count, errors), "Import Complete", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            self.log("[HARbringer] Error in import_all_to_sitemap: %s" % str(e))
            traceback.print_exc(file=self._stdout)
            JOptionPane.showMessageDialog(None, "Error: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
