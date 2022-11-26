package burp.Application;

import burp.*;
import burp.Bootstrap.CustomBurpParameters;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;

import java.io.PrintWriter;
import java.util.List;

public class HostScan {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;
    public PrintWriter stdout;


    private IHttpRequestResponse requestResponse;
    private IHttpRequestResponse vulnRequestResponse;
    private CustomBurpParameters requestParameters;
    private List<String> payloads;
    private YamlReader yamlReader;
    private IRequestInfo iRequestInfo;
    private Boolean isVuln = false;
    private CustomBurpUrl customBurpUrl;
    public HostScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, CustomBurpParameters requestParameters,CustomBurpUrl customBurpUrl) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.requestResponse = requestResponse;
        this.requestParameters = requestParameters;
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.payloads = this.yamlReader.getStringList("Application.hostPayloads");
        this.iRequestInfo = this.helpers.analyzeRequest(requestResponse);
        this.customBurpUrl= customBurpUrl;
        this.runHostScan();

    }

    private void runHostScan(){
        List<String> requestHeader = this.getRequestHeaders();
        String[] firstHeader = requestHeader.get(0).split(" ");
        for(String payload:this.payloads){
            if(this.customBurpUrl.getRequestQuery()==null&&this.iRequestInfo.getMethod()=="GET"){
                String newFirstHeader = "GET "+firstHeader[1]+payload+" "+firstHeader[2];
                requestHeader.set(0,newFirstHeader);
            }else if(this.requestParameters.isEmptyParameters()){
                String newFirstHeader = "GET "+firstHeader[1]+payload+" "+firstHeader[2];
                requestHeader.set(0,newFirstHeader);
            }else{
                String newFirstHeader = "GET " + getTargetPath(firstHeader[1]) + this.getParametersPayload(payload) + " " + firstHeader[2];
                requestHeader.set(0,newFirstHeader);
            }
            requestHeader.removeIf(header -> header.startsWith("Content-Type"));
            String body = "";
            byte[] requestBody = body.getBytes();
            byte[] newRequest = this.helpers.buildHttpMessage(requestHeader,requestBody);
            IHttpService httpService = this.requestResponse.getHttpService();
            IHttpRequestResponse newRequestResponse = this.callbacks.makeHttpRequest(httpService,newRequest);
            if(this.isHostVuln(newRequestResponse)){
                this.vulnRequestResponse=newRequestResponse;
                this.isVuln = true;
                return;
            }
        }
        return;
    }


    //  获取请求头
    private List<String> getRequestHeaders(){
        return this.iRequestInfo.getHeaders();
    }

    private String getTargetPath(String fistHeader_1){
        String[] firstHeader_split = fistHeader_1.split("\\?");
        return firstHeader_split[0];
    }

    //  获取参数payload
    private String getParametersPayload(String hostPayload){
        String parametersPayload = "?";
        for (IParameter parameter : this.requestParameters.getParameters()) {
            String name = parameter.getName();
            parametersPayload = parametersPayload + name + "=" + hostPayload + "&";
        }
        return parametersPayload;
    }



    private Boolean isHostVuln(IHttpRequestResponse newRequestResponse){
        byte[] response = newRequestResponse.getResponse();
        List<String> analyzedResponse = this.helpers.analyzeResponse(response).getHeaders();
        for(String headers : analyzedResponse){
            if(headers.contains("Set-Host-Header-Response")){
                return true;
            }
        }
        return false;
    }

    public IHttpRequestResponse getVulnRequestResponse(){
        return this.vulnRequestResponse;
    }

    public Boolean getIsVuln(){
        return this.isVuln;
    }
}