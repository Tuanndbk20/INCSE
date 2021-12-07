package INCSE.serverHttp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.text.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import INCSE.AccessRequest.accessRequest;

public class httpServer {
	final static int port = 9998;

	public static void main(String[] args) throws Exception {

		HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);// truoc la dien so 9999
		System.out.println("httpServer start at port: " + port);
		server.createContext("/INCSE/ticket", new MyHandler());
		server.setExecutor(null); // creates a default executor

		ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);

		server.start();
	}

	static class MyHandler implements HttpHandler {
		public void handle(HttpExchange httpExchange) throws IOException {
			String requestParamValue = null;

			System.out.println(httpExchange.getRequestMethod());

			if ("GET".equals(httpExchange.getRequestMethod())) {

				// requestParamValue = handleGetRequest(httpExchange);

			} else if ("POST".equals(httpExchange)) {

				// requestParamValue = handlePostRequest(httpExchange);
				handlePostRequest(httpExchange);
			}
			handleResponse(httpExchange, requestParamValue);
		}

		private void handleResponse(HttpExchange httpExchange, String requestParamValue) throws IOException {
			// OutputStream outputStream = httpExchange.getResponseBody();
			StringBuilder htmlBuilder = new StringBuilder();
			// requestParamValue=requestParamValue.replace("\n", "<br>");

			htmlBuilder.append("<html>").append("<body>").append("<h1>").append(requestParamValue).append("</h1>")
					.append("</body>").append("</html>");

			// String htmlResponse = StringEscapeUtils.escapeHtml4(htmlBuilder.toString());
			// // for what !?

			String htmlResponse = htmlBuilder.toString();

//			htmlResponse = requestParamValue;
//			System.out.println(htmlResponse);

			httpExchange.sendResponseHeaders(200, htmlResponse.length());
			OutputStream os = httpExchange.getResponseBody();
			os.write(htmlResponse.getBytes());
			os.close();

		}

		private void handlePostRequest(HttpExchange httpExchange) throws IOException {
			// TODO create a db
			System.out.println("Running in handle Post ");
			// String address = httpExchange.getRemoteAddress().toString();

			StringBuilder sb = new StringBuilder();
			InputStream ios = httpExchange.getRequestBody();
			int i;
			while ((i = ios.read()) != -1) {
				sb.append((char) i);
			}
			String jsonStr = sb.toString();

			Object obj = JSONValue.parse(jsonStr);
			JSONObject jsonObject = (JSONObject) obj;
			String nonce1 = (String) jsonObject.get("nonce1");
			String Qu = (String) jsonObject.get("Qu");
			String ticket = (String) jsonObject.get("Ticket");

			System.out.println("nonce1: " + nonce1);
			System.out.println("Qu: " + Qu);
			System.out.println("Ticket: " + ticket);

			// 2 to 5
			String[] dataTicket = accessRequest.authenticationTicket(Qu, ticket, nonce1).split("\\|");

			String AEID = dataTicket[0];
			String tokenID = dataTicket[1];
			String regTimestampBytes = dataTicket[2];

			// post DAS
			processTokenID(AEID,tokenID,regTimestampBytes);
			
			// 7

			String htmlResponse = "OK";
			httpExchange.sendResponseHeaders(200, htmlResponse.length());
			OutputStream os = httpExchange.getResponseBody();
			os.write(htmlResponse.getBytes());
			os.close();

		}
		
		//Post DAS
		final static CloseableHttpClient httpclient = HttpClients.createSystem();
		public static void processTokenID(String AEID, String tokenID, String regTimestampBytes) {	
					try {
						HttpPost httpPost = new HttpPost("http://localhost:8080/AuthorizationServer/ResourceClientRegistration");
						
						JsonObject jsonBody = new JsonObject();
						jsonBody.addProperty("AEID", AEID);
						jsonBody.addProperty("tokenID", tokenID);
						jsonBody.addProperty("regTimestampBytes", regTimestampBytes);
						Gson gson = new GsonBuilder().create();
						String body = gson.toJson(jsonBody);
						StringEntity content = new StringEntity(body);
						httpPost.setEntity(content);
						CloseableHttpResponse resp = httpclient.execute(httpPost);
						System.out.println(resp.toString());
						HttpEntity entityP = resp.getEntity();
						System.out.println(EntityUtils.toString(entityP, "UTF-8"));
						EntityUtils.consume(entityP);
						resp.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
		}
	}
}
