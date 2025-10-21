import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

public class WebhookServer {
    public static void main(String[] args) throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(2306), 10);
        httpServer.createContext("/java_webhook", new WebhookHandler());
        httpServer.start();
    }
}
