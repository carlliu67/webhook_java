import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class WebhookHandler implements HttpHandler {
    public void handle (HttpExchange exchange) {
        String method = exchange.getRequestMethod();

        System.out.println("method: " + method);
        
        if (method.contains("GET")) {
            doGet(exchange);

        } else if (method.contains("POST")) {
            doPost(exchange);
        } else {
            System.out.println("method: " + method + "is illegal");
        }

    }

    private static Map<String,String> formData2Dic(String formData ) {
        Map<String,String> result = new HashMap<>();
        if(formData== null || formData.trim().isEmpty()) {
            return result;
        }
        final String[] items = formData.split("&");
        Arrays.stream(items).forEach(item ->{
            final String[] keyAndVal = item.split("=");
            if( keyAndVal.length == 2) {
                try {
                    final String key = URLDecoder.decode( keyAndVal[0], "utf8");
                    final String val = URLDecoder.decode( keyAndVal[1], "utf8");
                    result.put(key,val);
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        return result;
    }
    /**
     * 补上Base64编码中缺失的末尾填充符'='
     * @param base64 缺失'='的Base64字符串
     * @return 补齐后的Base64字符串
     */
    public static String padBase64(String base64) {
        if (base64 == null || base64.isEmpty()) {
            return base64;
        }
        int length = base64.length();
        int remainder = length % 4;
        // 根据余数判断需要补充的'='数量
        switch (remainder) {
            case 2:
                return base64 + "==";
            case 3:
                return base64 + "=";
            default: // 余数为0（无需补充）或1（无效Base64，此处直接返回原字符串）
                return base64;
        }
    }

    private void doGet(HttpExchange exchange) {
        String queryString = exchange.getRequestURI().getQuery();
        Map<String, String> queryStringInfo = formData2Dic(queryString);
        String checkStr = padBase64(queryStringInfo.get("check_str"));
        String decodedData;
        String timestamp = exchange.getRequestHeaders().get("timestamp").get(0);
        String nonce = exchange.getRequestHeaders().get("nonce").get(0);
        String signature = exchange.getRequestHeaders().get("signature").get(0);
//        System.out.println("timestamp：" + timestamp + " nonce：" + nonce + " signature：" + signature);
        String checkSignature = Sha1Util.calSignature(WebhookConfig.token, timestamp, nonce, checkStr);
//        System.out.println("checkSignature：" + checkSignature);

        if (checkSignature.contentEquals(signature)) {
            try {
                // 配置了EncodingAESKey时需要进行解密操作
                if (WebhookConfig.encodingAESKey.length() > 1) {
                    try {
                        decodedData = DecryptUtil.decrypt(checkStr, WebhookConfig.encodingAESKey);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Base64.Decoder decoder = Base64.getDecoder();
                    decodedData = new String(decoder.decode(checkStr));
                }
                // 验证通过时需要返回base64解码和解密后的decodedData参数，并且HTTP 头部响应200
//                System.out.println("decodedData:" + decodedData);
                exchange.sendResponseHeaders(200, decodedData.length());
                OutputStream os = exchange.getResponseBody();
                os.write(decodedData.getBytes());
                os.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            try {
                // 验证不通过时报错
                String response = "check signature failed";
                System.out.println(response);
                exchange.sendResponseHeaders(400, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void doPost(HttpExchange exchange) {
        String timestamp = exchange.getRequestHeaders().get("timestamp").get(0);
        String nonce = exchange.getRequestHeaders().get("nonce").get(0);
        String signature = exchange.getRequestHeaders().get("signature").get(0);
        String postBody;
        PostMsg rawData;
        String decodedMsg;
//        System.out.println("timestamp：" + timestamp + " nonce：" + nonce + " signature：" + signature);
        try {
            postBody = IOUtils.toString(exchange.getRequestBody(), "UTF-8");
            Gson gson = new Gson();
            rawData = gson.fromJson(postBody, PostMsg.class);
//            System.out.println(rawData.data);
        } catch (Exception e) {
            System.out.println(Arrays.toString(e.getStackTrace()));
            throw new RuntimeException(e);
        }

        String checkSignature = Sha1Util.calSignature(WebhookConfig.token, timestamp, nonce, rawData.data);
//        System.out.println("checkSignature：" + checkSignature);

        if (checkSignature.contentEquals(signature)) {
            // 配置了EncodingAESKey时需要进行解密操作
            if (WebhookConfig.encodingAESKey.length() > 1) {
                try {
                    decodedMsg = DecryptUtil.decrypt(rawData.data, WebhookConfig.encodingAESKey);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            } else {
                Base64.Decoder decoder = Base64.getDecoder();
                decodedMsg = new String(decoder.decode(rawData.data));
            }

            try {
                // 验证通过时固定的字符串，并且HTTP 头部响应200
                String response = "successfully received callback";
                System.out.println(response);
                exchange.sendResponseHeaders(200, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            ////////////
            //对post消息进行处理
            System.out.println(decodedMsg);
            ////////////
        } else {
            try {
                // 验证不通过时报错
                String response = "check signature failed";
                System.out.println(response);
                exchange.sendResponseHeaders(400, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
