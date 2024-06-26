package one.colla.teamspace.domain;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import one.colla.common.domain.BaseEntity;
import one.colla.teamspace.domain.vo.TagName;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "tags")
public class Tag extends BaseEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "teamspace_id", nullable = false, updatable = false)
	private Teamspace teamspace;

	@OneToMany(mappedBy = "tag", fetch = FetchType.LAZY)
	private final List<UserTeamspace> userTeamspaces = new ArrayList<>();

	@Embedded
	private TagName tagName;

	private Tag(TagName tagName, Teamspace teamspace) {
		this.tagName = tagName;
		this.teamspace = teamspace;
	}

	public String getTagNameValue() {
		return tagName.getValue();
	}

	public static Tag createTagForTeamspace(String tagName, Teamspace teamspace) {
		Tag tag = new Tag(TagName.from(tagName), teamspace);
		teamspace.addTag(tag);
		return tag;
	}
}
