package com.duideduo.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



/**
 * @author syncwt
 * @version V1.0
 * @Title: ${file_name}
 * @Package ${package_name}
 * @Description: RSA加解密，验 证，生成证书
 * @date ${date} ${time}
 */
public class RSAUtil {


    /**
     * 签名算法
     */
    public static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    /**
     * 生成公角与私钥
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String[] getRSAKey() throws NoSuchAlgorithmException {
        //1.初始化秘钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //秘钥长度
        keyPairGenerator.initialize(512);
        //初始化秘钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //公钥
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        //私钥
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        String publicStringKey = Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
        String privateStringKey = Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());

        return new String[]{publicStringKey, privateStringKey};
    }

    /**
     * 根据String 的key获取公钥对像
     * @param key
     * @return
     */
    public static PublicKey getPublicKeyByString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyByte = Base64.getDecoder().decode(key);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec); //转换为公角
        return publicKey;
    }

    /**
     * 根据String 的key获取私钥对像
     * @param key
     * @return
     */
    public static PrivateKey getPrivateKeyByString(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyByte = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec); //转换为私角
        return privateKey;
    }

    /**
     * 公角加密
     * @param param
     * @param publicKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] publicKeyEncode(byte[] param,PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        //初始化解密
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return  cipher.doFinal(param);
    }

    /**
     * 私角解密
     * @param param
     * @param privateKey
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] privateKeyDecode(byte[] param,PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA");
        //初始化解密
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return  cipher.doFinal(param);
    }

    /**
     * RSA签名认证
     * @param content
     * @return
     */
    public static byte[] sign(byte[] content,PrivateKey priKey)
    {
        try
        {

            Signature signature = Signature.getInstance(SIGN_ALGORITHMS);
            signature.initSign(priKey);
            signature.update( content);
            return signature.sign();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 验证RSA签名
     * @param content
     * @param sign
     * @param pubKey
     * @return
     */
    public static boolean checkSign(byte[] content, byte[] sign, PublicKey pubKey )
    {
        try
        {
            Signature signature = Signature
                    .getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update( content);

            return signature.verify( sign );

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return false;
    }




    public final static void main(String[] args) throws Exception {
        /*
         * 测试用的,生成后的公/私钥
         * */
        String  publicKey ="MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMfySi/iKzbED4sDbUScxQvk5SxSBNp35zB0OizQ4SmxpPkqHKuL78LWqJ6qS/+02yIv9Wv1dp+ui/o7StGfuJkCAwEAAQ==";
        String  privateKey = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAx/JKL+IrNsQPiwNtRJzFC+TlLFIE2nfnMHQ6LNDhKbGk+Socq4vvwtaonqpL/7TbIi/1a/V2n66L+jtK0Z+4mQIDAQABAkEAmaSdTV5GRrcyGmhvtqGg6Rri38PG5vnsNVeavIVmAFqd7eMu9wufDm7jIrwF7DUhEjkdS5C/mJ1du2jPoolQAQIhAOJeB44RrQc08dn18vTCWe7LEVNXz+5E5EAw+s7vNdJBAiEA4h7Zsooej+4VB9QxlUGHQ6f0drQkLK8Rbm4/ASJBoFkCICCNBOkZAZiXtG9zPoyTpfsAmG0zo2LP5UKVyHsZStQBAiEAzGlRKXp86GY08s/bRu9nBT1W3Nw6e36Dxo25PSAnrXkCIGhLQwYUQhQfBZ1CJ0kGlD5xlGonaVjySdp2w0Ud3oCS";

        PublicKey puk =   com.duideduo.rsa.RSAUtil.getPublicKeyByString(publicKey);
        PrivateKey prk =   com.duideduo.rsa.RSAUtil.getPrivateKeyByString(privateKey);

        String param = "hellovictor,your are so smart";
        byte[] result = Base64.getDecoder().decode("TBU8Gz7A0vg+WqG5etZ4IlYGbIE6li0XvtUKMMJDACurxe79WA5BULoxXlPHrk7d9T/XzN4iQbRGrZ0RRL7iQg==");//TTDRSAUtil.publicKeyEncode(param.getBytes(),puk);
        param = new String( com.duideduo.rsa.RSAUtil.privateKeyDecode(result,prk));
        System.out.println(param);

        //------签名认证
        byte[] sign =  com.duideduo.rsa.RSAUtil.sign("victor".getBytes(),prk);//生成签名
        System.out.println( com.duideduo.rsa.RSAUtil.checkSign("victor".getBytes(),sign,puk)); //验证内容签名

    }
}