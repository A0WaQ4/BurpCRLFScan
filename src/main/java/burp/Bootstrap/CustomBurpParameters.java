package burp.Bootstrap;

import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.util.List;

public class CustomBurpParameters {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;


    private IHttpRequestResponse requestResponse;
    private List<IParameter> parameters;
    private IRequestInfo iRequestInfo;
    private List<String> requestHeaders;

    public CustomBurpParameters(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.requestResponse = requestResponse;
        this.iRequestInfo = this.helpers.analyzeRequest(this.requestResponse);
        this.parameters = iRequestInfo.getParameters();
        this.requestHeaders = iRequestInfo.getHeaders();
    }

    /**
     * 判断请求包中是否存在参数
     *
     * @return
     */
    public boolean isEmptyParameters(){
        return this.parameters.isEmpty();
    }

    /**
     * 判断请求是否为json
     *
     * @return
     */
    public boolean isJson(){
        for(String requestHeader:this.requestHeaders){
            if(requestHeader.startsWith("Content-Type:")&&requestHeader.contains("application/json"))
                return true;
        }
        return false;
    }

    /**
     * 判断请求是否为普通类型
     *
     * @return
     */
    public boolean isXFormUrlencoded(){
        for(String requestHeader:this.requestHeaders){
            if(requestHeader.startsWith("Content-Type:")&&requestHeader.contains("application/x-www-form-urlencoded"))
                return true;
        }
        return false;
    }


    /**
     * 获取请求的参数
     *
     * @return
     */
    public List<IParameter> getParameters(){
        return this.parameters;
    }

}
