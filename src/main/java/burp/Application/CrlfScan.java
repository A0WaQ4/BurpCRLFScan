package burp.Application;

import burp.*;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.CustomBurpParameters;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.lang3.StringUtils;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class CrlfScan {
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
                    String newFirstHeader = requestMethod + " " + getTargetPath(firstHeader[1]) + this.getParametersPayload(payload) + " " + firstHeader[2];
                    requestHeader.set(0,newFirstHeader);
                }
            }
            if(requestMethod == "POST"){
                if(thisRequestBody == null){
                    body = payload;
                }else{
                    if(this.requestParameters.isJson()&&this.isJSON(thisRequestBody.replaceAll("(\\[(.*?)])","\"test\""))){
                        body = this.analyseJson(thisRequestBody.replaceAll("(\\[(.*?)])","\"test\""),payload).toString();
                    }
                    if(this.requestParameters.isXFormUrlencoded()){
                        body = this.getParametersPayload(payload);
                    }
                }
            }
//            if(this.customBurpUrl.getRequestQuery()==null&&this.iRequestInfo.getMethod()=="GET"){
//                String newFirstHeader = "GET "+firstHeader[1]+payload+" "+firstHeader[2];
//                requestHeader.set(0,newFirstHeader);
//            }else if(this.requestParameters.isEmptyParameters()){
//                String newFirstHeader = "GET "+firstHeader[1]+payload+" "+firstHeader[2];
//                requestHeader.set(0,newFirstHeader);
//            }else{
//                String newFirstHeader = "GET " + getTargetPath(firstHeader[1]) + this.getParametersPayload(payload) + " " + firstHeader[2];
//                requestHeader.set(0,newFirstHeader);
//            }
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
    public  JSONObject analyseJson(String jsonData , String payload) {
        JSONObject jsonObjectResult = new JSONObject();
        //把传入String类型转换成JSONObject对象
        JSONObject jsonObject = JSON.parseObject(jsonData);
        for (Map.Entry<String, Object> entry : jsonObject.entrySet()) {
            String key = entry.getKey();
            Object o = entry.getValue();
            if(o instanceof Integer || o instanceof Boolean || o == null){
                jsonObjectResult.put(key, entry.getValue());
            }else if(o instanceof String){
                jsonObjectResult.put(key, entry.getValue()+payload);
            }else if(!StringUtils.isEmpty(String.valueOf(entry.getValue())) && isJSON(entry.getValue().toString())){
                jsonObjectResult.put(key, analyseJson(entry.getValue().toString(),payload));
            }
        }


        return jsonObjectResult;
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
