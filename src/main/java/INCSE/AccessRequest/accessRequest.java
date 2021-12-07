package INCSE.AccessRequest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.sql.Connection;
import java.util.Date;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import org.bouncycastle.crypto.digests.SHA256Digest;

public class accessRequest {
	// byte[] resources = null;
	public static final String Ks = "taokhoaks123456789";
	public static final String AEID = "123456789";
	public static final String URL = "URLResources";
	public static final int nonceSize = 12;

	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	private static String convertHexToString(String hex) {

		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		// 49204c6f7665204a617661 split into two characters 49, 20, 4c...
		for (int i = 0; i < hex.length() - 1; i += 2) {

			// grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			// convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			// convert the decimal to character
			sb.append((char) decimal);

			temp.append(decimal);
		}

		return sb.toString();
	}

	// concatByteArray:Chuyen String ve byte
	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()];
		digest.update(data, 0, data.length);
		digest.doFinal(hash, 0);
		return hash;
	}

	public static String authenticationTicket(String Qu, String ticket, String n) {
		// Creat Kt=(Qu||Ks)
		byte[] IDprivRandConcat = concatByteArrays(hexStringToByteArray(Qu), hexStringToByteArray(Ks));
		byte[] Kt = sha256(IDprivRandConcat);
		System.out.println("Kt :" + toHex(Kt));

		// Decrypt Ticket = Dkt(Ticket)--> TokenID, Rn,Texp
		byte[] resources = null;
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(false, new ParametersWithIV(new KeyParameter(Kt), hexStringToByteArray(n)));
		byte[] tmp = new byte[ticket.length()];
		int len = ccm.processBytes(hexStringToByteArray(ticket), 0, ticket.length(), tmp, 0);
		try {
			len += ccm.doFinal(tmp, len);
			resources = new byte[len];
			System.arraycopy(tmp, 0, resources, 0, len);
			System.out.println("resources: " + toHex(resources));
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String appData = convertHexToString(toHex(resources));
		String[] data = appData.split("\\|\\|");

		String tokenID = data[0];
		String Rn = data[1];
		String Texp = data[2];

		System.out.println("tokenID: " + tokenID);
		System.out.println("Resounce name Rn:  " + Rn);
		System.out.println("Expired Time Texp:  " + Texp);

		/* Generate a timestamp Ts */
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);

		return AEID + "|" + tokenID + "|" + regTimestampBytes;
	}

	public static String EncryptURL(String Sk) {

		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		SecureRandom random = new SecureRandom();
		random = new SecureRandom();
		byte[] nonce3 = new byte[nonceSize];
		random.nextBytes(nonce3); // Fill the nonce with random bytes
		System.out.println("nonce3 = " + toHex(nonce3));

		// Encrypt the URL
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(true, new ParametersWithIV(new KeyParameter(hexStringToByteArray(Sk)), nonce3));
		byte[] EU = new byte[URL.length() + 8];
		int len = ccm.processBytes(hexStringToByteArray(URL), 0, URL.length(), hexStringToByteArray(URL), 0);
		try {
			len += ccm.doFinal(EU, len);
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Eu " + toHex(EU));
		
		/* Generate a timestamp Ts */
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);
		
		return toHex(EU)+"|"+ toHex(regTimestampBytes) + "|" + nonce3;
	}
}
