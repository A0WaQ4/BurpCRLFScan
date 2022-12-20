package burp.Application;

import burp.*;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.CustomBurpParameters;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import com.alibaba.fastjson.JSON;
import org.dom4j.DocumentHelper;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

    /**
     * 漏洞扫描执行
     */
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
//                    String s = this.getParametersPayload(payload);
                    String[] firstHeaderParameters = firstHeader[1].split("\\?");
                    String newFirstHeader = requestMethod + " " + getTargetPath(firstHeader[1]) + "?" + this.analyseParameters(firstHeaderParameters[1],payload) + " " + firstHeader[2];
                    requestHeader.set(0,newFirstHeader);
                }
            }
            if(requestMethod == "POST"){
                if(thisRequestBody == null){
                    body = payload;
                }else{
                    switch (this.analyzeRequest().getContentType()){
                        case 3:
                            body = this.analyseXML(thisRequestBody , payload);
                            break;
                        case 4:
                            body = this.analyseJson(thisRequestBody, payload);
                            break;
                        default:
                            body = this.analyseParameters(thisRequestBody, payload);
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


    public IRequestInfo analyzeRequest() {
        return this.helpers.analyzeRequest(this.requestResponse.getRequest());
    }

    /**
     * 获取请求头
     *
     * @return 返回请求头的列表
     */
    private List<String> getRequestHeaders(){
        return this.iRequestInfo.getHeaders();
    }

    /**
     * 返回请求包路径
     *
     * @param fistHeader 请求包的第一行
     * @return 返回request路径的字符串
     */
    private String getTargetPath(String fistHeader){
        String[] firstHeaderSplit = fistHeader.split("\\?");
        return firstHeaderSplit[0];
    }


    /**
     * 获取返回包
     *
     * @return 返回Response的byte类型数据
     */
    private byte[] getResponse(){
        return this.newResponseRequest.getResponse();
    }

    /**
     * 判断是否存在可控Response头或者CRLF漏洞
     *
     * @return 存在漏洞=true 不存在=false
     */
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
     * 分析request包中参数字符串
     *
     * @param parametersData 参数字符串
     * @param payload crlfPayload
     * @return 返回拼接后的参数字符串
     */
    private String analyseParameters(String parametersData, String payload){
        String parametersResult = "";
        String[] parametersDataAnalyse = parametersData.split("&");
        for(int i = 0 ; i < parametersDataAnalyse.length ; i++){
            String[] parameter = parametersDataAnalyse[i].split("=");
            switch (isJSONOrXML(parameter[1])){
                case 0:
                    parametersResult = parametersResult + parameter[0] + "=" + payload + "&";
                    break;
                case 1:
                    parametersResult = parametersResult + parameter[0] + "=" + analyseJson(parameter[1],payload) + "&";
                    break;
                case 2:
                    parametersResult = parametersResult + parameter[0] + "=" + analyseXML(parameter[1],payload) + "&";
                    break;
            }
        }
        return parametersResult.substring(0 , parametersResult.length()-1);
    }


    /**
     * 解析json字符串，普通和嵌套类型都可
     *
     * @param jsonData 请求包的json数据
     * @param payload  crlf的payload
     * @return 返回添加payload的json字符串
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
     * 解析XML字符串
     *
     * @param XMLData
     * @param payload
     * @return 返回添加了payload的字符串
     */
    public String analyseXML(String XMLData, String payload){
        List<String> list = new ArrayList<String>();
        Pattern pattern = Pattern.compile(">(.*?)</");
        Matcher m = pattern.matcher(XMLData);
        while (m.find()) {
            list.add(m.group(1));
        }
        for (String str: list){
            XMLData = XMLData.replace(">" + str + "</", ">" + payload + "</");
        }
        return XMLData;
    }

    /**
     * 返回str为json或xml
     *
     * @param str 需要判断的字符串
     * @return JSON = 1、 XML = 2、 others = 0
     */
    public int isJSONOrXML(String str) {
        try {
            JSON.parse(str.replaceAll("(\\[(.*?)])","\"test\""));
            return 1;
        } catch (Exception e) {
        }
        try {
            DocumentHelper.parseText(str);
            return 2;
        } catch (Exception e) {
        }

        return 0;
    }


    /**
     * 返回存在漏洞到requesResponse
     *
     * @return 返回本次扫描存在漏洞的requestResponse
     */
    public IHttpRequestResponse getVulnRequestResponse(){
        return this.vulnRequestResponse;
    }

    /**
     * 返回是否存在漏洞的判断
     *
     * @return 返回本次扫描是否存在漏洞
     */
    public Boolean getIsVuln(){
        return this.ifVuln;
    }
}
