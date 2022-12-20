package burp;

import burp.Application.CrlfScan;
import burp.Bootstrap.CustomBurpHelpers;
import burp.Bootstrap.CustomBurpParameters;
import burp.Bootstrap.CustomBurpUrl;
import burp.Bootstrap.YamlReader;
import burp.UI.*;

import javax.swing.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener ,IContextMenuFactory{
    public static String NAME="CRLFScan";
    public Tags tags;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private YamlReader yamlReader;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.tags = new Tags(callbacks, NAME);

        callbacks.setExtensionName(NAME);
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);

        // 配置文件
        this.yamlReader = YamlReader.getInstance(callbacks);
        // 基本信息输出
        this.stdout.println(basicInformationOutput());
    }
    /**
     * 基本信息输出
     * @return
     */
    private static String basicInformationOutput() {
        String str1 = "===================================\n";
        String str2 = String.format("LOADING %s SUCCESS\n", NAME);
        String str3 = String.format("GitHub:https://github.com/A0WaQ4/BurpCRLFScan\n");
        String str4 = String.format("Author:A0WaQ4\n");
        String str5 = "===================================\n";
        String detail = str1 + str2 + str3 + str4 + str5;
        return detail;
    }
    @Override
    public void extensionUnloaded() {

    }

    /**
     * 进行被动扫描
     * @param baseRequestResponse 基础的请求返回包
     * @return null
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        List<String> domainNameBlacklist = this.yamlReader.getStringList("scan.domainName.blacklist");

        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);
        CustomBurpParameters baseBurpParameters = new CustomBurpParameters(this.callbacks,baseRequestResponse);


        // 判断域名黑名单
        if (domainNameBlacklist != null && domainNameBlacklist.size() >= 1) {
            if (isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameBlacklist)) {
                return null;
            }
        }

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }
        // 传入不同payload分别对Response Header进行检测
        CrlfScan hostScan = new CrlfScan(this.callbacks,baseRequestResponse,baseBurpParameters,baseBurpUrl,"Application.hostPayloads");
        // 如果发现了存在Response可控 添加到面板 进行下一步扫描
        if(hostScan.getIsVuln()){
            int tagId = this.tags.add(
                    "Scanning",
                    this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                    baseBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                    "[*] found Response Header Controlled , now testing CRLF-Injection",
                    String.valueOf(baseRequestResponse.getResponse().length),
                    hostScan.getVulnRequestResponse()
            );
            CrlfScan crlfScan = new CrlfScan(this.callbacks,baseRequestResponse,baseBurpParameters,baseBurpUrl,"Application.payloads");
            // 如果发现了CRLF漏洞 更新面板 否则更新为未发现漏洞
            if(crlfScan.getIsVuln()){
                this.tags.save(
                        tagId,
                        "CRLF Injection",
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                        "[+] found CRLF Injection",
                        String.valueOf(baseRequestResponse.getResponse().length),
                        crlfScan.getVulnRequestResponse()
                );
                issues.add(new CustomScanIssue(
                        baseBurpUrl.getHttpRequestUrl(),
                        "CRLF-Injection",
                        0,
                        "High",
                        "Certain",
                        null,
                        null,
                        "detail",
                        null,
                        new IHttpRequestResponse[]{crlfScan.getVulnRequestResponse()},
                        crlfScan.getVulnRequestResponse().getHttpService()
                ));
                return issues;
            }else{
                this.tags.save(
                        tagId,
                        "Response Header Controlled",
                        this.helpers.analyzeRequest(baseRequestResponse).getMethod(),
                        baseBurpUrl.getHttpRequestUrl().toString(),
                        this.helpers.analyzeResponse(baseRequestResponse.getResponse()).getStatusCode() + "",
                        "[*] just found Response Header Controlled",
                        String.valueOf(baseRequestResponse.getResponse().length),
                        hostScan.getVulnRequestResponse()
                );
            }
        }

        // 输出UI
        return null;
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return 是=true 否=false
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }


    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
        return null;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     *
     * @param burpUrl 目标url
     * @return 是 = true, 否 = false
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {
        if (!this.yamlReader.getBoolean("urlBlackListSuffix.config.isStart")) {
            return false;
        }

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = this.yamlReader.getStringList("urlBlackListSuffix.suffixList");
        if (suffixList == null || suffixList.size() == 0) {
            return false;
        }

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

}