package burp.Application;

import burp.*;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.CustomBurpParameters;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import com.alibaba.fastjson.JSON;

import java.io.PrintWriter;
import java.util.List;

public class CrlfScan {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;


    private IHttpRequestResponse requestResponse;
    private IHttpRequestResponse vulnRequestResponse;
    private CustomBurpParameters requestParameters;
    private List<String> payloads;
    private YamlReader yamlReader;
    private IRequestInfo iRequestInfo;
    private Boolean ifVuln = false;
    private CustomBurpUrl customBurpUrl;
    private IHttpRequestResponse newResponseRequest;
    private CustomBurpHelpers customBurpHelpers;

    public CrlfScan(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, CustomBurpParameters requestParameters,CustomBurpUrl customBurpUrl,String payload) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.requestResponse = requestResponse;
        this.requestParameters = requestParameters;
        this.yamlReader = YamlReader.getInstance(callbacks);
        this.payloads = this.yamlReader.getStringList(payload);
        this.iRequestInfo = this.helpers.analyzeRequest(requestResponse);
        this.customBurpUrl= customBurpUrl;
        this.customBurpHelpers = new CustomBurpHelpers(callbacks);
        this.runCrlfScan();

    }

    private void runCrlfScan(){
        List<String> requestHeader = this.getRequestHeaders();
        String[] firstHeader = requestHeader.get(0).split(" ");
        String requestMethod = this.iRequestInfo.getMethod();
        String body = "";
        String thisRequestBody = this.customBurpHelpers.getHttpRequestBody(this.requestResponse.getRequest());
        for(String payload:this.payloads){
            if(requestMethod == "GET"){
                if(this.customBurpUrl.getRequestQuery() == null){
                    String newFirstHeader = requestMethod + " " + firstHeader[1] + payload + " " + firstHeader[2];
                    requestHeader.set(0,newFirstHeader);
                }else{
                    String s = this.getParametersPayload(payload);
                    String newFirstHeader = requestMethod + " " + getTargetPath(firstHeader[1]) + s.substring(0,s.length()-1) + " " + firstHeader[2];
                    requestHeader.set(0,newFirstHeader);
                }
            }
            if(requestMethod == "POST"){
                if(thisRequestBody == null){
                    body = payload;
                }else{
                    if(this.requestParameters.isJson()&&this.isJSON(thisRequestBody.replaceAll("(\\[(.*?)])","\"test\""))){
                        body = this.analyseJson(thisRequestBody,payload);
                    }
                    if(this.requestParameters.isXFormUrlencoded()){
                        String s = this.getParametersPayload(payload);
                        body = s.substring(1,s.length()-1);
                    }
                }
            }

            byte[] requestBody = body.getBytes();
            byte[] newRequest = this.helpers.buildHttpMessage(requestHeader,requestBody);
            IHttpService httpService = this.requestResponse.getHttpService();
            this.newResponseRequest = this.callbacks.makeHttpRequest(httpService,newRequest);
            if(this.isVuln()){
                this.vulnRequestResponse=newResponseRequest;
                this.ifVuln = true;
                return;
            }
        }
        return;
    }


//  获取请求头
    private List<String> getRequestHeaders(){
        return this.iRequestInfo.getHeaders();
    }

    private String getTargetPath(String fistHeader){
        String[] firstHeaderSplit = fistHeader.split("\\?");
        return firstHeaderSplit[0];
    }

//  获取参数payload
    private String getParametersPayload(String crlfPayload){
        String parametersPayload = "?";
        for (IParameter parameter : this.requestParameters.getParameters()) {
            String name = parameter.getName();
            parametersPayload = parametersPayload + name + "=" + crlfPayload + "&";
        }
        return parametersPayload;
    }


//  获取返回包
    private byte[] getResponse(){
        return this.newResponseRequest.getResponse();
    }

//    判断是否存在CRLF漏洞
    private Boolean isVuln(){
        List<String> analyzedResponse = this.helpers.analyzeResponse(this.getResponse()).getHeaders();
        for(String headers : analyzedResponse){
            if(headers.startsWith("Set-CRLF-injection") || headers.startsWith(" Set-CRLF-injection")||headers.contains("Set-Host-Header-Response")){
                return true;
            }
        }
        return false;
    }


    /**
     * 解析json字符串，普通和嵌套类型都可
     * @param jsonData
     * @return
     */
    public String  analyseJson(String jsonData , String payload) {
        String jsonResult = "";
        boolean j = false;
        for(int i=0;i<jsonData.length();i++){
            if(j&&jsonData.charAt(i) == '"'){
                j = false;
                continue;
            }
            if(j){
                continue;
            }
            if(jsonData.charAt(i) == '"'&&jsonData.charAt(i-1) == ':'){
                jsonResult = jsonResult + "\"" + payload + "\"";
                j = true;
            }else{
                jsonResult = jsonResult + jsonData.charAt(i);
            }

        }


        return jsonResult;
    }

    /**
     * 判断传入的参数是否为json格式
     * @param str
     * @return
     */
    public  boolean isJSON(String str) {
        boolean result;
        try {
            JSON.parse(str);
            result = true;
        } catch (Exception e) {
            result = false;
        }
        return result;
    }

//    返回存在漏洞到requesRespons
    public IHttpRequestResponse getVulnRequestResponse(){
        return this.vulnRequestResponse;
    }

//    返回是否存在漏洞的判断
    public Boolean getIsVuln(){
        return this.ifVuln;
    }
}
