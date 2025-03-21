package one.colla.infra.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;

@Slf4j
@Component
public class MailService {
	private static final String UTF_8 = "UTF-8";

	private final JavaMailSender javaMailSender;
	private final String adminEmail;

	public MailService(JavaMailSender javaMailSender, @Value("${spring.mail.admin-email}") String adminEmail) {
		this.javaMailSender = javaMailSender;
		this.adminEmail = adminEmail;
	}

	public void sendMail(MimeMessage message) {
		try {
			javaMailSender.send(message);
			log.info("이메일 전송 완료");
		} catch (MailException e) {
			log.error("이메일 전송 실패:", e);
			throw new CommonException(ExceptionCode.UNEXPECTED_ERROR);
		}
	}

	public MimeMessage createMessage(String to, String subject, String content) {
		MimeMessage mimeMessage = javaMailSender.createMimeMessage();
		try {
			MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, UTF_8);
			helper.setFrom(adminEmail);
			helper.setTo(to);
			helper.setSubject(subject);
			helper.setText(content, true);
			return mimeMessage;
		} catch (MessagingException e) {
			log.error("이메일 메시지 생성 오류 ", e);
			return null;
		}
	}
}
