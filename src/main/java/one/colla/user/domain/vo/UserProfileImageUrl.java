package one.colla.user.domain.vo;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import one.colla.common.domain.vo.Url;

@Embeddable
@EqualsAndHashCode(callSuper = false)
@Getter
public class UserProfileImageUrl extends Url {

	@Column(name = "profile_image_url")
	private String value;

	public UserProfileImageUrl() {
		this.value = null;
	}

	public UserProfileImageUrl(final String value) {
		validate(value);
		this.value = value;
	}

	public static UserProfileImageUrl from(final String url) {
		return new UserProfileImageUrl(url);
	}

	public UserProfileImageUrl change(final String newUrl) {
		return new UserProfileImageUrl(newUrl);
	}

}
