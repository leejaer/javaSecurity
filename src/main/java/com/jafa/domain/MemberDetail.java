package com.jafa.domain;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import lombok.Getter;

@Getter
public class MemberDetail extends User{
	
	private static final long serialVersionUID = 6985945701734583315L;
	
	private MemberVO memberVO;
	
	
	public MemberDetail(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}


	public MemberDetail(MemberVO vo) {
		super(vo.getMemberId(), vo.getPassword(),
				vo.getAuthList().stream()
				.map(auth-> new SimpleGrantedAuthority(auth.getMemberType().toString()))//MemberType에 toString 안 붙었을때 있을 때는 Name()
				.collect(Collectors.toList()));
		this.memberVO = vo;
	}

	
}
