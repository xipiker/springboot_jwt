package pers.xipiker.springboot_jwt.common;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.util.Date;

/**
 * @Auther: xipiker
 * @Date: 2019-8-6
 * @Description: JWT
 */
public class JwtUtils {

    // 过期时间一个星期
    private static final long EXPIRE_TIME = 7 * 24 * 60 * 60 * 1000;
    // 签名秘钥
    private static final String SECRET = "xipiker";

    /**
     * 校验token是否正确
     *
     * @param token    密钥
     * @param userCode 用户名
     * @return 是否正确
     */
    public static boolean verify(String token, String userCode) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("userCode", userCode)
                    .build();
            verifier.verify(token);
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    /**
     * 获得token中的信息无需secret解密也能获得
     *
     * @return token中包含的用户名
     */
    public static String getUserCode(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("userCode").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 生成签名,指定时间后过期,一经生成不可修改，令牌在指定时间内一直有效
     * @param userCode 用户名
     * @return 加密的token
     */
    public static String createJWT(String userCode) {
        try {
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            // 附带username信息
            return JWT.create()
                    .withClaim("userCode", userCode)
                    .withExpiresAt(date)
                    .sign(algorithm);
        } catch (UnsupportedEncodingException e) {
            return null;
        }
    }

}
