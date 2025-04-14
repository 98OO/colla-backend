package one.colla.chat.application;

import java.util.Comparator;
import java.util.List;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import one.colla.chat.application.dto.request.CreateChatChannelRequest;
import one.colla.chat.application.dto.request.UpdateChatChannelNameRequest;
import one.colla.chat.application.dto.response.ChatChannelInfoDto;
import one.colla.chat.application.dto.response.ChatChannelMessageAttachmentDto;
import one.colla.chat.application.dto.response.ChatChannelMessageAuthorDto;
import one.colla.chat.application.dto.response.ChatChannelMessageResponse;
import one.colla.chat.application.dto.response.ChatChannelMessagesResponse;
import one.colla.chat.application.dto.response.ChatChannelsResponse;
import one.colla.chat.application.dto.response.CreateChatChannelResponse;
import one.colla.chat.domain.ChatChannel;
import one.colla.chat.domain.ChatChannelMessage;
import one.colla.chat.domain.ChatChannelMessageRepository;
import one.colla.chat.domain.ChatChannelRepository;
import one.colla.chat.domain.UserChatChannel;
import one.colla.chat.domain.UserChatChannelRepository;
import one.colla.chat.domain.vo.ChatChannelName;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;
import one.colla.teamspace.application.TeamspaceService;
import one.colla.teamspace.application.dto.response.UnreadMessageCountResponse;
import one.colla.teamspace.domain.Teamspace;
import one.colla.teamspace.domain.TeamspaceRole;
import one.colla.teamspace.domain.UserTeamspace;

@Slf4j
@Service
@RequiredArgsConstructor
public class ChatChannelService {

	private static final int PAGE_REQUEST_ZERO_OFFSET = 0;

	private final TeamspaceService teamspaceService;
	private final ChatChannelRepository chatChannelRepository;
	private final UserChatChannelRepository userChatChannelRepository;
	private final ChatChannelMessageRepository chatChannelMessageRepository;

	@Transactional
	public CreateChatChannelResponse createChatChannel(CustomUserDetails userDetails, Long teamspaceId,
		CreateChatChannelRequest request) {

		final Teamspace teamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId).getTeamspace();
		final ChatChannel createdChatChannel = chatChannelRepository.save(
			ChatChannel.of(teamspace, request.chatChannelName()));
		final List<UserChatChannel> participants = createdChatChannel.participateAllTeamspaceUser(
			teamspace.getUserTeamspaces());
		userChatChannelRepository.saveAll(participants);

		teamspace.addChatChannel(createdChatChannel);

		log.info("채팅 채널 생성 - 팀스페이스 Id: {}, 생성한 사용자 Id: {}, 생성한 채팅 채널 Id: {}",
			teamspaceId, userDetails.getUserId(), createdChatChannel.getId());
		return CreateChatChannelResponse.from(createdChatChannel);
	}

	@Transactional(readOnly = true)
	public ChatChannelsResponse getChatChannels(CustomUserDetails userDetails, Long teamspaceId) {

		final Teamspace teamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId).getTeamspace();

		List<ChatChannelInfoDto> chatChannels = teamspace.getChatChannels().stream()
			.map(cc -> createChatChannelInfoDto(cc, userDetails.getUserId()))
			.sorted(Comparator.comparing(ChatChannelInfoDto::lastChatCreatedAt,
				Comparator.nullsLast(Comparator.reverseOrder())))
			.toList();
		log.info("채팅 채널 목록 조회 - 팀스페이스 Id: {}, 조회한 사용자 Id: {}", teamspaceId, userDetails.getUserId());
		return ChatChannelsResponse.from(chatChannels);
	}

	public ChatChannelInfoDto createChatChannelInfoDto(ChatChannel chatChannel, Long userId) {

		Long lastChatId = chatChannel.getLastChatId();

		int unreadMessageCount = calculateUnreadMessageCount(userId, chatChannel);
		if (lastChatId == null) {
			return ChatChannelInfoDto.of(chatChannel, null, null, unreadMessageCount);
		}

		return chatChannelMessageRepository.findById(lastChatId)
			.map(msg -> {
				String contentValue = (msg.getContent() != null) ? msg.getContent().getValue() : null;
				return ChatChannelInfoDto.of(chatChannel, contentValue, msg.getCreatedAt(), unreadMessageCount);
			})
			.orElseGet(() -> ChatChannelInfoDto.of(chatChannel, null, null, 0));
	}

	@Transactional
	public void updateChatChannelName(CustomUserDetails userDetails, Long teamspaceId,
		UpdateChatChannelNameRequest request) {

		final Teamspace teamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId).getTeamspace();

		processChatChannelNameUpdate(request, teamspace);

		log.info("채팅 채널 이름 수정 - 팀스페이스 Id: {}, 수정한 사용자 Id: {}, 수정한 채팅 채널 Id: {}",
			teamspaceId, userDetails.getUserId(), request.chatChannelId());
	}

	public int calculateUnreadMessageCount(Long userId, ChatChannel chatChannel) {
		return userChatChannelRepository.findByUserIdAndChatChannelId(userId, chatChannel.getId())
			.map(userChatChannel -> {
				Long lastReadMessageId = userChatChannel.getLastReadMessageId();
				if (lastReadMessageId == null) {
					return chatChannelMessageRepository.countByChatChannel(chatChannel);
				} else {
					return chatChannelMessageRepository.countByChatChannelAndIdGreaterThan(chatChannel,
						lastReadMessageId);
				}
			})
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_USER_CHAT_CHANNEL));
	}

	private void processChatChannelNameUpdate(UpdateChatChannelNameRequest request, Teamspace teamspace) {
		ChatChannel chatChannel = teamspace.getChatChannels().stream()
			.filter(cc -> cc.getId().equals(request.chatChannelId()))
			.findFirst()
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_CHAT_CHANNEL));
		ChatChannelName chatChannelName = ChatChannelName.from(request.chatChannelName());
		chatChannel.updateChatChannelName(chatChannelName);
	}

	@Transactional(readOnly = true)
	public ChatChannelMessagesResponse getChatChanelMessages(CustomUserDetails userDetails, Long teamspaceId,
		Long chatChannelId, Long beforeChatMessageId, int limit) {

		final Teamspace teamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId).getTeamspace();
		final ChatChannel chatChannel = getChatChannel(teamspace, chatChannelId);

		validateBeforeChatMessageId(beforeChatMessageId, chatChannel);

		List<ChatChannelMessage> messages = fetchChatChannelMessages(chatChannel, beforeChatMessageId, limit);
		List<ChatChannelMessageResponse> chatChannelMessageResponses = convertToChatChannelMessageResponse(messages);

		log.info("채팅 채널 메세지 조회 - 팀스페이스 Id: {}, 조회한 사용자 Id: {}, 채팅 채널 Id: {} ",
			teamspaceId, userDetails.getUserId(), chatChannel.getId());
		return ChatChannelMessagesResponse.from(chatChannelMessageResponses);
	}

	@Transactional
	public void deleteChatChannel(CustomUserDetails userDetails, Long teamspaceId, Long chatChannelId) {
		final UserTeamspace userTeamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId);
		final ChatChannel chatChannel = getChatChannel(userTeamspace.getTeamspace(), chatChannelId);

		if (!userTeamspace.getTeamspaceRole().equals(TeamspaceRole.LEADER)) {
			throw new CommonException(ExceptionCode.ONLY_LEADER_ACCESS);
		}

		userTeamspace.getTeamspace().removeChatChannel(chatChannel);
		chatChannelMessageRepository.deleteAllByChatChannel(chatChannel);
		chatChannelRepository.delete(chatChannel);
	}

	@Transactional(readOnly = true)
	public UnreadMessageCountResponse getTeamspaceUnreadMessageCount(
		final CustomUserDetails userDetails,
		final Long teamspaceId
	) {
		final Teamspace teamspace = teamspaceService.getUserTeamspace(userDetails, teamspaceId).getTeamspace();

		int totalUnreadCount = teamspace.getChatChannels().stream()
			.mapToInt(chatChannel -> calculateUnreadMessageCount(userDetails.getUserId(), chatChannel))
			.sum();

		log.info("팀스페이스 안읽은 메시지 개수 조회 - 팀스페이스 Id: {}, 조회한 사용자 Id: {}", teamspaceId, userDetails.getUserId());
		return UnreadMessageCountResponse.of(totalUnreadCount);
	}

	private ChatChannel getChatChannel(Teamspace teamspace, Long chatChannelId) {
		return teamspace.getChatChannels()
			.stream()
			.filter(ch -> ch.getId().equals(chatChannelId))
			.findFirst()
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_CHAT_CHANNEL));
	}

	private void validateBeforeChatMessageId(Long beforeChatMessageId, ChatChannel chatChannel) {
		if (beforeChatMessageId != null && chatChannelMessageRepository.findByIdAndChatChannel(
			beforeChatMessageId, chatChannel).isEmpty()) {
			throw new CommonException(ExceptionCode.NOT_FOUND_CHAT_CHANNEL_MESSAGE);
		}
	}

	private List<ChatChannelMessage> fetchChatChannelMessages(ChatChannel chatChannel, Long beforeChatMessageId,
		int limit) {
		PageRequest pageRequest = PageRequest.of(PAGE_REQUEST_ZERO_OFFSET, limit);
		return chatChannelMessageRepository.findChatChannelMessageByChatChannelAndCriteria(
			chatChannel, beforeChatMessageId, pageRequest);
	}

	private List<ChatChannelMessageResponse> convertToChatChannelMessageResponse(List<ChatChannelMessage> messages) {
		return messages.stream()
			.map(msg -> {
				ChatChannelMessageAuthorDto author = ChatChannelMessageAuthorDto.from(msg.getUser());
				List<ChatChannelMessageAttachmentDto> attachments = getMessageAttachmentDtos(msg);
				return ChatChannelMessageResponse.of(msg, author, attachments);
			}).toList();
	}

	private static List<ChatChannelMessageAttachmentDto> getMessageAttachmentDtos(ChatChannelMessage msg) {
		return msg.getChatChannelMessageAttachments()
			.stream()
			.map(ChatChannelMessageAttachmentDto::from)
			.toList();
	}
}
