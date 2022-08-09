package com.callor.todo.service.auth;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.callor.todo.model.AuthorityVO;
import com.callor.todo.model.UserVO;
import com.callor.todo.persistance.UserDao;

@Service("authenticationProvider")
public class AuthenticationProviderImpl  implements AuthenticationProvider{
	
	@Autowired
	private UserDao userDao;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		//로그인을 수행한 사용자의 ID와 비번을 추출
		String username = (String)authentication.getPrincipal();
		String password = (String)authentication.getCredentials();
		
		UserVO userVO = userDao.findById(username);
		
		if(userVO == null) {
			throw  new UsernameNotFoundException(username+ "이 없다");
		}
		
		if(!userVO.getPassword().equals(password)) {
			throw new BadCredentialsException("비밀번호 오류!");
		}
		
		List<AuthorityVO> authList = userDao.select_auths(username);
		List<GrantedAuthority> grantList = new ArrayList<>();
		
		/*
		 * 사용자(username)비번(password) 권한리스트 만으로 Token 발행하기
		 * 토큰을 발행하는 최소한의 요건
		 * 이렇게 토큰을 발행하면
		 * JSP에서 principal.username, principal.password 항목은 참조할 수 있으나
		 * principal.email, principal.realname 등의 항목은 참조할 수 없다
 		return new UsernamePasswordAuthenticationToken(username, password, grantList);
		 */
		
		//UserVO 객체와 권한리스트로 토큰 발행하기
		//Token에 UserVO가 담기게 되고 security에서 제공하는 user정보 이외의 항목들을
		//JSP에서 자유롭게 principal 객체를 통해 접근 할 수 있다.
 		return new UsernamePasswordAuthenticationToken(userVO, null, grantList);
 		
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return true;
	}

}
