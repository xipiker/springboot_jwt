package pers.xipiker.springboot_jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import pers.xipiker.springboot_jwt.common.JwtUtils;

/**
 * @author: xipiker
 * @Date: 2019-8-6
 * @Description: JwtController
 */

@Controller
public class JwtController {

    /**
     * 生成用户对应的token
     * @param username
     * @return token
     */
    @ResponseBody
    @RequestMapping(value="login", method = RequestMethod.POST)
    public String login(String username) {
         String JWT = JwtUtils.createJWT(username);
         return JWT;
    }

    /**
     * 验证token是否有效
     * @param token
     * @param username
     * @return String
     */
    @ResponseBody
    @RequestMapping(value="verifyToken", method = RequestMethod.POST)
    public String verifyToken(String token, String username) {
        Boolean flag = JwtUtils.verify(token, username);
        if(flag){
            return "token success";
        }else {
            return "token error";
        }
    }

    /**
     * 无需SECRET，直接获取用户信息
     * @param token
     * @return userCode
     */
    @ResponseBody
    @RequestMapping(value="findUserCode", method = RequestMethod.POST)
    public String findUserCode(String token) {
        return JwtUtils.getUserCode(token);
    }
}
