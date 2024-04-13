package one.colla.chat.domain;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Column;
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
import one.colla.teamspace.domain.Teamspace;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "chat_channels")
public class ChatChannel extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "teamspace_id", nullable = false)
	private Teamspace teamspace;

	@OneToMany(mappedBy = "chatChannel", fetch = FetchType.LAZY)
	private final List<UserChatChannel> userChatChannels = new ArrayList<>();

	@OneToMany(mappedBy = "chatChannel", fetch = FetchType.LAZY)
	private final List<ChatChannelMessage> chatChannelMessages = new ArrayList<>();

	@Column(name = "name", nullable = false, length = 50)
	private String name;

	@Column(name = "last_chat_id")
	private Long lastChatId;

}
