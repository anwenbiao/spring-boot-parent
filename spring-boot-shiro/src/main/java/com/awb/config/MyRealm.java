package com.awb.config;

import com.awb.dao.UserDao;
import com.awb.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

/**
 * 自定义的realm  进行权限与用户的认知
 * @author wenbiao.an
 *         2018/6/12
 */
public class MyRealm  extends AuthorizingRealm {

    @Autowired
    private UserDao userDao;
    /**
     * 权限的认证
     * @param principal
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principal) {
        System.out.println("权限认证方法：MyShiroRealm.doGetAuthenticationInfo()");
        User token = (User) SecurityUtils.getSubject().getPrincipal();
        String userName = token.getUserName();
        SimpleAuthorizationInfo info =  new SimpleAuthorizationInfo();

        //实际开发，当前登录用户的角色和权限信息是从数据库来获取的，我这里写死是为了方便测试
        Set<String> roleSet = new HashSet();
        roleSet.add("user");
        info.setRoles(roleSet);

        Set<String> permissionSet = new HashSet();
        permissionSet.add("save");
        info.setStringPermissions(permissionSet);
        return info;

    }

    /**
     * 用户的认证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("身份认证");

        String userName = (String) token.getPrincipal();
       //从数据库获取用户信息
        User user = userDao.findByUserName(userName);
        if (user == null) {
            throw new AccountException("用户为空");
        }

        SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(user, user.getPassword(),getName());
        System.out.println("================>"+simpleAuthenticationInfo);
        //MD5 加密+加盐+多次加密
       // SimpleAuthenticationInfo authcInfo = new SimpleAuthenticationInfo(user, user.getPassword(), ByteSource.Util.bytes(salt), this.getName());
        return simpleAuthenticationInfo;
    }

    @Override
    public String getName() {
        return "MyRealm";
    }
}
