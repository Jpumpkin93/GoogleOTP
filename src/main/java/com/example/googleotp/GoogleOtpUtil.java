package com.example.googleotp;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;

public class GoogleOtpUtil {

    public static HashMap<String, String> generate(String name, String host){
        HashMap<String, String> map = new HashMap<>();

        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);

        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        byte[] bEncodedKey = codec.encode(secretKey);

        String encodedKey = new String(bEncodedKey);  // 생성된 key
        String url = getQRBarcodeURL(name, host, encodedKey);


        map.put("encodedKey", encodedKey);
        map.put("url", url);

        return map;
    }

    public static boolean checkCode(String userCode, String otpkey){
        long otpnum = Integer.parseInt(userCode);  // OTP 앱에 표시되는 6자리 숫자
        long wave = new Date().getTime()/30000;  // OTP의 주기(초)
        boolean result = false;
        try{
            Base32 codec = new Base32();
            byte[] decodedKey = codec.decode(otpkey);
            int window = 3;
            for(int i = -window; i <= window; ++i){
                long hash = verify_code(decodedKey, wave + i);
                if(hash == otpnum) result = true;
            }
        }catch (InvalidKeyException | NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return result;
    }

    private static int verify_code(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException{
        byte[] data = new byte[8];
        long value = t;
        for(int i = 8; i-- > 0; value >>>= 8){
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20-1] & 0xF;

        long truncatedHash = 0;

        for(int i = 0; i<4; ++i){
            truncatedHash <<=8;

            truncatedHash |=(hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF ;
        truncatedHash %= 1000000;

        return (int)truncatedHash;
    }

    public static String getQRBarcodeURL(String user, String host, String secret) {
        // QR코드 주소 생성
        String format2 = "http://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
        return String.format(format2, user, host, secret);
    }
}
