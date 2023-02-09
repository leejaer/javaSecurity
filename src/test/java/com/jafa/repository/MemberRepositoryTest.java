package com.jafa.repository;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import com.jafa.config.RootConfig;
import com.jafa.config.SecurityConfig;
import com.jafa.config.ServletConfig;
import com.jafa.domain.AuthVO;
import com.jafa.domain.MemberType;
import com.jafa.domain.MemberVO;
import com.jafa.service.MemberService;

import lombok.extern.log4j.Log4j;
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {RootConfig.class, SecurityConfig.class, ServletConfig.class})
@WebAppConfiguration
@Log4j
public class MemberRepositoryTest {

	@Autowired
	MemberRepository memberRepository;
	
	@Autowired
	AuthRepository authRepository;	
	
	@Autowired
	MemberService memberService;
	
	
	@Test
	@Ignore
	public void test1() {
		MemberVO vo = MemberVO.builder()
				.memberId("admin")
				.password("1234")
				.email("lee@naver.com")
				.build();
		memberRepository.save(vo);
		AuthVO authVO = AuthVO.builder()
				.memberId(vo.getMemberId())
				.memberType(MemberType.ROLE_ASSOCIATE_MEMBER)
				.ordinal(MemberType.ROLE_ASSOCIATE_MEMBER.ordinal())
				.build();
		authRepository.save(authVO);		
	}
	


	@Test
	public void test2() {
		AuthVO auth = new AuthVO("admin", MemberType.ROLE_ADMIN);
		memberService.updateMemberType(auth);
	}
	
	@Test
	@Ignore
	public void test3() {
		AuthVO auth = new AuthVO("leekwanghyup", MemberType.ROLE_REGULAR_MEMBER);
		memberService.updateMemberType(auth);
	}

}
