package com.awb.dao;

import com.awb.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

/**
 * @author wenbiao.an
 *         2018/6/12
 */
@Mapper
public interface UserDao {

    @Select("select username userName,password password from sys_user where username=#{userName}")
     User findByUserName(String userName);
}
