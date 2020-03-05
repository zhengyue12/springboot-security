package com.example.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * <h3>springboot-security</h3>
 * <p></p>
 *
 * @author : 你的名字
 * @date : 2020-03-03 13:45
 **/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //定制请求的授权规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //开启自动配置的登录功能,效果如果没有权限，回到登陆页面
        http.formLogin().usernameParameter("username").passwordParameter("password").loginPage("/userlogin");
        //1./login来到登录页
        //2.重定向/login?error表示登录失败
        //3.更多详细规定
        //4.规定post形式请求方式，/login代表处理登录
        //5.一旦定制loginPage；那么loginPage的post请求就是登录

        //开启自动配置的注销功能
        http.logout().logoutSuccessUrl("/");  //注销成功回到首页
        //1.访问/logout表示用户注销，清空session
        //2.注销成功会返回 /login?logout 页面

        //开启记住我功能
        http.rememberMe().rememberMeParameter("remeber");
        //登录成功以后，将cookie发给浏览器保存，以后带上这个cookie，只要通过检测就可以免登录
        //点击注销会删除cookie
    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        auth.inMemoryAuthentication()
                .passwordEncoder(new MyPasswordEncoder()) //加入自定义编码器
                .withUser("zhangsan").password("123456").roles("VIP1", "VIP2")
                .and()
                .withUser("lisi").password("123456").roles("VIP2", "VIP3")
                .and()
                .withUser("wangwu").password("123456").roles("VIP1", "VIP3");
    }
}
