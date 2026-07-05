package one.colla.file.domain.vo;

import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import one.colla.common.domain.vo.Url;
import one.colla.global.exception.VoException;

@Embeddable
@EqualsAndHashCode(callSuper = false)
@Getter
public class FileUrl extends Url {
	private static final List<String> ALLOWED_URL_PREFIXES = List.of(
		"https://cdn.colla.so/",
		"https://colla-v2-uploads-120766982296.s3.ap-northeast-2.amazonaws.com/"
	);

	@Column(name = "file_url", nullable = false)
	private String value;

	public FileUrl() {
		this.value = null;
	}

	public FileUrl(final String value) {
		validate(value);
		this.value = value;
	}

	public static FileUrl from(final String url) {
		return new FileUrl(url);
	}

	public FileUrl change(final String newUrl) {
		return new FileUrl(newUrl);
	}

	@Override
	protected void validate(final String url) {
		super.validate(url);

		boolean isValid = ALLOWED_URL_PREFIXES.stream().anyMatch(url::startsWith);
		if (!isValid) {
			throw new VoException("CDN Url 이 아닙니다.");
		}
	}
}
