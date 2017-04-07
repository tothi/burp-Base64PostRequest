package burp;

import java.awt.Component;
import java.util.Arrays;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Base64 decode / encode POST request data");
        callbacks.registerMessageEditorTabFactory(this);
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new Base64InputTab(controller, editable);
    }
    
    class Base64InputTab implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        
        public Base64InputTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }
        
        @Override
        public String getTabCaption() {
            return "Base64";
        }
        
        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }
        
        private byte[] getRequestData(byte[] content) {
            return Arrays.copyOfRange(content, helpers.analyzeRequest(content).getBodyOffset(), content.length);
        }
        
        // enable if request body is a valid base64 string       
        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            String p = "\\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)\\z";
            String req = new String(getRequestData(content));
            return isRequest && content != null && Pattern.matches(p, req);
        }
        
        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null) {
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {
                txtInput.setText(helpers.base64Decode(getRequestData(content)));
                txtInput.setEditable(editable);
            }
            currentMessage = content;
        }

        @Override
        public byte[] getMessage() {
            if (txtInput.isTextModified()) {
                byte[] body = helpers.base64Encode(txtInput.getText()).getBytes();
                byte[] header = Arrays.copyOfRange(currentMessage, 0, helpers.analyzeRequest(currentMessage).getBodyOffset());
                byte[] req = Arrays.copyOf(header, header.length + body.length);
                System.arraycopy(body, 0, req, header.length, body.length);
                return req;
            } else {
                return currentMessage;
            }
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }
        
        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }
    }
}                

