package com.awb.controller;

import com.awb.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author wenbiao.an
 *         2018/6/12
 */
@Controller
public class LoginAction {

    @RequestMapping(value = "/login")
    public String login(HttpServletRequest request, Model model) throws Exception{
      /*  // 如果登陆失败从request中获取认证异常信息，shiroLoginFailure就是shiro异常类的全限定名
        String exceptionClassName = (String) request.getAttribute("shiroLoginFailure");
        // 根据shiro返回的异常类路径判断，抛出指定异常信息
        if (exceptionClassName != null) {
            if (UnknownAccountException.class.getName().equals(exceptionClassName)) {
                // 最终会抛给异常处理器
                model.addAttribute("message","账号不存在");
            } else if (IncorrectCredentialsException.class.getName().equals(exceptionClassName)) {
                model.addAttribute("message","用户名/密码错误");
            } else if ("randomCodeError".equals(exceptionClassName)) {
                model.addAttribute("message","验证码错误");
            } else {
                model.addAttribute("message","未知错误");
            }
        }*/
        // 此方法不处理登陆成功（认证成功），shiro认证成功会自动跳转到上一个请求路径
        // 登陆失败还到login页面
        return "login";
    }

    @RequestMapping(value = "submitLogin",method = RequestMethod.POST)
    @ResponseBody
    public  Map<String,Object>  submitLogin(User user){
        Map<String, Object> resultMap = new LinkedHashMap();
        try {

            UsernamePasswordToken token = new UsernamePasswordToken(user.getUserName(), user.getPassword());
            SecurityUtils.getSubject().login(token);

            System.out.println("登录成功");
        } catch (Exception e) {
            resultMap.put("status", 500);
            resultMap.put("message", e.getMessage());
            System.out.println("失败");
        }
        return resultMap;


    }

    @RequestMapping("/index")
    public String index(){
        return "index";
    }

    @RequestMapping(value="logout",method =RequestMethod.GET)
    @ResponseBody
    public Map<String,Object> logout(){
        Map<String, Object> resultMap = new LinkedHashMap<String, Object>();
        try {
            //退出
            SecurityUtils.getSubject().logout();
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
        return resultMap;


    }



}
