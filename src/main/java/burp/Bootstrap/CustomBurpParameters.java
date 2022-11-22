package burp.Bootstrap;

import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

public class CustomBurpParameters {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;
    public PrintWriter stdout;


    private IHttpRequestResponse requestResponse;
    private List<IParameter> parameters;
    private IRequestInfo iRequestInfo;

    public CustomBurpParameters(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.requestResponse = requestResponse;
        this.iRequestInfo = this.helpers.analyzeRequest(this.requestResponse);
        this.parameters = iRequestInfo.getParameters();
    }

    // 判断请求包中是否存在可控参数
    public boolean isEmptyParameters(){
        return this.parameters.isEmpty();
    }


    //获取请求的参数
    public List<IParameter> getParameters(){
        return this.parameters;
    }

    public URL getUrl(){
        return this.iRequestInfo.getUrl();
    }
}
