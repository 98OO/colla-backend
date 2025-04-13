package one.colla.chat.application;

import static one.colla.common.fixtures.ChatChannelFixtures.*;
import static one.colla.common.fixtures.ChatChannelMessageFixtures.*;
import static one.colla.common.fixtures.TeamspaceFixtures.*;
import static one.colla.common.fixtures.UserFixtures.*;
import static one.colla.common.fixtures.UserTeamspaceFixtures.*;
import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;

import one.colla.chat.application.dto.request.CreateChatChannelRequest;
import one.colla.chat.application.dto.request.UpdateChatChannelNameRequest;
import one.colla.chat.application.dto.response.ChatChannelMessagesResponse;
import one.colla.chat.application.dto.response.ChatChannelsResponse;
import one.colla.chat.application.dto.response.CreateChatChannelResponse;
import one.colla.chat.domain.ChatChannel;
import one.colla.chat.domain.ChatChannelMessage;
import one.colla.chat.domain.ChatChannelMessageRepository;
import one.colla.chat.domain.ChatChannelRepository;
import one.colla.chat.domain.UserChatChannel;
import one.colla.chat.domain.UserChatChannelRepository;
import one.colla.common.ServiceTest;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;
import one.colla.teamspace.application.TeamspaceService;
import one.colla.teamspace.application.dto.response.UnreadMessageCountResponse;
import one.colla.teamspace.domain.Teamspace;
import one.colla.teamspace.domain.UserTeamspace;
import one.colla.user.domain.User;

class ChatChannelServiceTest extends ServiceTest {

	@Autowired
	private TeamspaceService teamspaceService;

	@Autowired
	private ChatChannelMessageRepository chatChannelMessageRepository;

	@Autowired
	private ChatChannelRepository chatChannelRepository;

	@Autowired
	private UserChatChannelRepository userChatChannelRepository;

	@Autowired
	private ChatChannelService chatChannelService;

	User USER1;
	User USER2;
	CustomUserDetails USER1_DETAILS;
	Teamspace OS_TEAMSPACE;
	UserTeamspace USER1_OS_USERTEAMSPACE;
	UserTeamspace USER2_OS_USERTEAMSPACE;

	@BeforeEach
	void setUp() {
		USER1 = testFixtureBuilder.buildUser(USER1());
		USER2 = testFixtureBuilder.buildUser(USER2());
		USER1_DETAILS = createCustomUserDetailsByUser(USER1);
		OS_TEAMSPACE = testFixtureBuilder.buildTeamspace(OS_TEAMSPACE());
		USER1_OS_USERTEAMSPACE = testFixtureBuilder.buildUserTeamspace(LEADER_USERTEAMSPACE(USER1, OS_TEAMSPACE));
		USER2_OS_USERTEAMSPACE = testFixtureBuilder.buildUserTeamspace(MEMBER_USERTEAMSPACE(USER2, OS_TEAMSPACE));
	}

	@Nested
	@DisplayName("채팅 채널 생성시")
	class CreateChatChannelTest {

		CreateChatChannelRequest request;
		CreateChatChannelResponse response;

		@Test
		@DisplayName("생성에 성공한다.")
		void createChatChannel_Success() {

			// given
			request = new CreateChatChannelRequest("새로운 채팅 채널");

			// when
			response = chatChannelService.createChatChannel(USER1_DETAILS, OS_TEAMSPACE.getId(), request);

			// then
			final Optional<ChatChannel> savedChatChannel = chatChannelRepository.findById(response.chatChannelId());

			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(savedChatChannel).hasValueSatisfying((chatChannel) -> {
					assertThat(response.chatChannelId()).isEqualTo(chatChannel.getId());
					assertThat(chatChannel.getUserChatChannels()).hasSize(2);
				});

			});
		}

		@Test
		@DisplayName("팀스페이스에 참여하고 있지 않은 사용자면 예외가 발생한다.")
		void createChatChannel_Fail() {
			// given
			User OTHER_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails OTHER_USER_DETAILS = createCustomUserDetailsByUser(OTHER_USER);

			// when & then
			assertThatThrownBy(
				() -> chatChannelService.createChatChannel(OTHER_USER_DETAILS, OS_TEAMSPACE.getId(), request))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.FORBIDDEN_TEAMSPACE.getMessage());

		}
	}

	@Nested
	@DisplayName("채팅 채널 조회시")
	class GetChatChannelTest {

		ChatChannel FRONTEND_CHAT_CHANNEL;
		ChatChannel BACKEND_CHAT_CHANNEL;
		ChatChannelMessage CHAT_MESSAGE1;

		@BeforeEach
		void setUp() {
			/* 채팅 채널 생성 */
			FRONTEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			BACKEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(BACKEND_CHAT_CHANNEL(OS_TEAMSPACE));

			/* 팀스페이스에 채팅 채널 추가 */
			OS_TEAMSPACE.addChatChannel(FRONTEND_CHAT_CHANNEL);
			OS_TEAMSPACE.addChatChannel(BACKEND_CHAT_CHANNEL);

			/* 채팅 채널 유저 참가 */
			testFixtureBuilder.buildUserChatChannel(
				FRONTEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
			testFixtureBuilder.buildUserChatChannel(
				BACKEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));

			/* 채팅 채널 메세지 생성 */
			CHAT_MESSAGE1 = testFixtureBuilder.buildChatChannelMessage(
				CHAT_MESSAGE1(USER1, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));

			/* 채팅채널에 last 메세지 업데이트 */
			FRONTEND_CHAT_CHANNEL.updateLastChatMessage(CHAT_MESSAGE1.getId());
		}

		@Test
		@DisplayName("조회에 성공한다.")
		void getChatChannel_Success() {

			// when
			ChatChannelsResponse response = chatChannelService.getChatChannels(USER1_DETAILS, OS_TEAMSPACE.getId());

			//then

			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response.chatChannels().size()).isEqualTo(2);
				softly.assertThat(response.chatChannels().get(0).name())
					.isEqualTo(FRONTEND_CHAT_CHANNEL.getChatChannelName().getValue());
				softly.assertThat(response.chatChannels().get(0).lastChatMessage()).isEqualTo(
					CHAT_MESSAGE1.getContent().getValue());
				softly.assertThat(response.chatChannels().get(1).name())
					.isEqualTo(BACKEND_CHAT_CHANNEL.getChatChannelName().getValue());
				softly.assertThat(response.chatChannels().get(1).lastChatMessage()).isEqualTo(
					null);

			});

		}

		@Test
		@DisplayName("팀스페이스 접근 권한이 없으면 예외가 발생한다.")
		void getChatChannel_Fail() {

			// given
			User OTHER_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails OTHER_USER_DETAILS = createCustomUserDetailsByUser(OTHER_USER);

			// when & then
			assertThatThrownBy(() -> chatChannelService.getChatChannels(OTHER_USER_DETAILS, OS_TEAMSPACE.getId()))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.FORBIDDEN_TEAMSPACE.getMessage());

		}

	}

	@Nested
	@DisplayName("채팅 채널 이름 수정시")
	class UpdateChatChannelNameTest {

		UpdateChatChannelNameRequest request;
		ChatChannel FRONTEND_CHAT_CHANNEL;
		String NEW_CHAT_CHANNEL_NAME = "새로운 채팅 채널 이름";

		@BeforeEach
		void setUp() {
			FRONTEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			OS_TEAMSPACE.addChatChannel(FRONTEND_CHAT_CHANNEL);
		}

		@Test
		@DisplayName("수정에 성공한다.")
		void updateChatChannelName_Success() {
			// given
			request = new UpdateChatChannelNameRequest(FRONTEND_CHAT_CHANNEL.getId(), NEW_CHAT_CHANNEL_NAME);

			// when
			chatChannelService.updateChatChannelName(USER1_DETAILS, OS_TEAMSPACE.getId(), request);

			// then
			final Optional<ChatChannel> updatedChatChannel = chatChannelRepository.findById(
				FRONTEND_CHAT_CHANNEL.getId());

			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(updatedChatChannel).hasValueSatisfying(chatChannel -> {
					assertThat(chatChannel.getChatChannelName().getValue()).isEqualTo(NEW_CHAT_CHANNEL_NAME);
				});
			});
		}

		@Test
		@DisplayName("팀스페이스 접근 권한이 없으면 예외가 발생한다.")
		void updateChatChannelName_Fail_NoAccess() {
			// given
			User OTHER_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails OTHER_USER_DETAILS = createCustomUserDetailsByUser(OTHER_USER);
			request = new UpdateChatChannelNameRequest(FRONTEND_CHAT_CHANNEL.getId(), NEW_CHAT_CHANNEL_NAME);

			// when & then
			assertThatThrownBy(
				() -> chatChannelService.updateChatChannelName(OTHER_USER_DETAILS, OS_TEAMSPACE.getId(), request))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.FORBIDDEN_TEAMSPACE.getMessage());
		}

		@Test
		@DisplayName("존재하지 않는 채팅 채널이면 예외가 발생한다.")
		void updateChatChannelName_Fail_NotFound() {
			// given
			request = new UpdateChatChannelNameRequest(999L, NEW_CHAT_CHANNEL_NAME);

			// when & then
			assertThatThrownBy(
				() -> chatChannelService.updateChatChannelName(USER1_DETAILS, OS_TEAMSPACE.getId(), request))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.NOT_FOUND_CHAT_CHANNEL.getMessage());
		}
	}

	@Nested
	@DisplayName("채팅 채널 메시지 조회시")
	class GetChatChannelMessagesTest {

		ChatChannel FRONTEND_CHAT_CHANNEL;
		ChatChannel BACKEND_CHAT_CHANNEL;

		@BeforeEach
		void setUp() {
			FRONTEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			BACKEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(BACKEND_CHAT_CHANNEL(OS_TEAMSPACE));

			/* 팀스페이스에 채팅 채널 추가 */
			OS_TEAMSPACE.addChatChannel(FRONTEND_CHAT_CHANNEL);
			OS_TEAMSPACE.addChatChannel(BACKEND_CHAT_CHANNEL);

			/* 채팅 채널 유저 참가 */
			testFixtureBuilder.buildUserChatChannel(
				FRONTEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
			testFixtureBuilder.buildUserChatChannel(
				BACKEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
		}

		@Test
		@DisplayName("조회에 성공한다.")
		void getChatChannelMessages_Success() {

			// given
			List<ChatChannelMessage> messages = new ArrayList<>();
			for (int i = 0; i < 100; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					RANDOM_CHAT_MESSAGE(USER1, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				messages.add(msg);
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}

			// when
			ChatChannelMessagesResponse response = chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId(), null, 50);

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.chatChannelMessages().size()).isEqualTo(50);
				softly.assertThat(response.chatChannelMessages().get(0).content())
					.isEqualTo(messages.get(messages.size() - 1).getContent().getValue());
			});
		}

		@Test
		@DisplayName("before 파라미터가 제공되었을 때의 동작을 검증한다.")
		void getChatChannelMessages_BeforeParameter() {
			// given
			List<ChatChannelMessage> messages = new ArrayList<>();
			for (int i = 0; i < 100; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					RANDOM_CHAT_MESSAGE(USER1, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				messages.add(msg);
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}
			ChatChannelMessage beforeMessage = messages.get(70);

			// when
			ChatChannelMessagesResponse response = chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId(), beforeMessage.getId(), 50);

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.chatChannelMessages().size()).isEqualTo(50);
				softly.assertThat(response.chatChannelMessages().get(0).content())
					.isEqualTo(messages.get(69).getContent().getValue());
			});
		}

		@Test
		@DisplayName("limit와 before 파라미터가 같이 사용되었을 때 동작을 검증한다.")
		void getChatChannelMessages_BeforeAndLimit() {
			// given
			List<ChatChannelMessage> messages = new ArrayList<>();
			for (int i = 0; i < 100; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					RANDOM_CHAT_MESSAGE(USER1, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				messages.add(msg);
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}
			ChatChannelMessage beforeMessage = messages.get(70);

			// when
			ChatChannelMessagesResponse response = chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId(), beforeMessage.getId(), 20);

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.chatChannelMessages().size()).isEqualTo(20);
				softly.assertThat(response.chatChannelMessages().get(0).content())
					.isEqualTo(messages.get(69).getContent().getValue());

				softly.assertThat(response.chatChannelMessages().get(19).content())
					.isEqualTo(messages.get(50).getContent().getValue());
			});
		}

		@Test
		@DisplayName("빈 결과를 검증한다.")
		void getChatChannelMessages_EmptyResult() {
			// when
			ChatChannelMessagesResponse response = chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), BACKEND_CHAT_CHANNEL.getId(), null, 50);

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.chatChannelMessages()).isEmpty();
			});
		}

		@Test
		@DisplayName("팀스페이스에 참여하고 있지 않으면 예외가 발생한다.")
		void getChatChannelMessages_TeamspaceAccessDenied() {
			// given
			User OTHER_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails OTHER_USER_DETAILS = createCustomUserDetailsByUser(OTHER_USER);

			// when & then
			assertThatThrownBy(() -> chatChannelService.getChatChanelMessages(
				OTHER_USER_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId(), null, 50))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.FORBIDDEN_TEAMSPACE.getMessage());
		}

		@Test
		@DisplayName("존재하지 않는 채팅 채널이면 예외가 발생한다.")
		void getChatChannelMessages_ChatChannelNotFound() {
			// when & then
			assertThatThrownBy(() -> chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), 999L, null, 50))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.NOT_FOUND_CHAT_CHANNEL.getMessage());
		}

		@Test
		@DisplayName("선택한 채팅 채널에 해당 채팅 메시지가 없으면 예외가 발생한다.")
		void getChatChannelMessages_ChatChannelMessageNotFound() {
			// when & then
			assertThatThrownBy(() -> chatChannelService.getChatChanelMessages(
				USER1_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId(), 999L, 50))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.NOT_FOUND_CHAT_CHANNEL_MESSAGE.getMessage());
		}
	}

	@Nested
	@DisplayName("채팅 채널 삭제시")
	class DeleteChatChannelTest {

		ChatChannel FRONTEND_CHAT_CHANNEL;
		ChatChannel BACKEND_CHAT_CHANNEL;
		List<ChatChannelMessage> messages = new ArrayList<>();

		@BeforeEach
		void setUp() {
			FRONTEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			BACKEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(BACKEND_CHAT_CHANNEL(OS_TEAMSPACE));

			/* 팀스페이스에 채팅 채널 추가 */
			OS_TEAMSPACE.addChatChannel(FRONTEND_CHAT_CHANNEL);
			OS_TEAMSPACE.addChatChannel(BACKEND_CHAT_CHANNEL);

			/* 채팅 채널 유저 참가 */
			testFixtureBuilder.buildUserChatChannel(
				FRONTEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
			testFixtureBuilder.buildUserChatChannel(
				BACKEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));

			for (int i = 0; i < 50; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					RANDOM_CHAT_MESSAGE(USER1, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				messages.add(msg);
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}
		}

		@Test
		@DisplayName("삭제에 성공한다.")
		void deleteChatChannel_Success() {
			// when
			chatChannelService.deleteChatChannel(USER1_DETAILS, OS_TEAMSPACE.getId(), FRONTEND_CHAT_CHANNEL.getId());

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(chatChannelRepository.findById(FRONTEND_CHAT_CHANNEL.getId())).isEmpty();
				softly.assertThat(OS_TEAMSPACE.getChatChannels().contains(FRONTEND_CHAT_CHANNEL)).isEqualTo(false);
				softly.assertThat(chatChannelMessageRepository.findChatChannelMessageByChatChannelAndCriteria(
					FRONTEND_CHAT_CHANNEL, null, PageRequest.of(0, 50))).isEmpty();
			});
		}

		@Test
		@DisplayName("팀스페이스 리더가 아니면 삭제에 실패한다.")
		void deleteChatChannel_Fail_NotLeader() {
			// given
			User RANDOM_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails MEMBER_DETAILS = createCustomUserDetailsByUser(RANDOM_USER);
			USER1_OS_USERTEAMSPACE = testFixtureBuilder.buildUserTeamspace(
				MEMBER_USERTEAMSPACE(RANDOM_USER, OS_TEAMSPACE));

			ChatChannel chatChannel = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			OS_TEAMSPACE.addChatChannel(chatChannel);
			testFixtureBuilder.buildUserChatChannel(
				chatChannel.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));

			// when & then
			assertThatThrownBy(
				() -> chatChannelService.deleteChatChannel(MEMBER_DETAILS, OS_TEAMSPACE.getId(), chatChannel.getId()))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.ONLY_LEADER_ACCESS.getMessage());
		}

		@Test
		@DisplayName("존재하지 않는 채널 삭제 시도시 예외가 발생한다.")
		void deleteChatChannel_Fail_ChannelNotFound() {
			// when & then
			assertThatThrownBy(() -> chatChannelService.deleteChatChannel(USER1_DETAILS, OS_TEAMSPACE.getId(), 999L))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.NOT_FOUND_CHAT_CHANNEL.getMessage());
		}
	}

	@Nested
	@DisplayName("팀스페이스 안읽은 메시지 개수 조회시")
	class GetTeamspaceUnreadMessageCountTest {

		ChatChannel FRONTEND_CHAT_CHANNEL;
		ChatChannel BACKEND_CHAT_CHANNEL;

		@BeforeEach
		void setUp() {
			/* 채팅 채널 생성 */
			FRONTEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(FRONTEND_CHAT_CHANNEL(OS_TEAMSPACE));
			BACKEND_CHAT_CHANNEL = testFixtureBuilder.buildChatChannel(BACKEND_CHAT_CHANNEL(OS_TEAMSPACE));

			/* 팀스페이스에 채팅 채널 추가 */
			OS_TEAMSPACE.addChatChannel(FRONTEND_CHAT_CHANNEL);
			OS_TEAMSPACE.addChatChannel(BACKEND_CHAT_CHANNEL);

			/* 채팅 채널 유저 참가 */
			testFixtureBuilder.buildUserChatChannel(
				FRONTEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
			testFixtureBuilder.buildUserChatChannel(
				BACKEND_CHAT_CHANNEL.participateAllTeamspaceUser(OS_TEAMSPACE.getUserTeamspaces()));
		}

		@Test
		@DisplayName("팀스페이스의 모든 채팅 채널에서 안읽은 메시지 개수의 합계를 반환한다")
		void getTeamspaceUnreadCount_Success() {
			// given
			// 첫 번째 채널에 메시지 5개 생성
			for (int i = 0; i < 5; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					CHAT_MESSAGE1(USER2, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}

			// 두 번째 채널에 메시지 3개 생성
			for (int i = 0; i < 3; i++) {
				ChatChannelMessage msg = testFixtureBuilder.buildChatChannelMessage(
					CHAT_MESSAGE1(USER2, OS_TEAMSPACE, BACKEND_CHAT_CHANNEL));
				BACKEND_CHAT_CHANNEL.updateLastChatMessage(msg.getId());
			}

			// USER1의 첫 번째 채널에서 3개 메시지를 읽음 표시
			UserChatChannel userChatChannel = userChatChannelRepository
				.findByUserIdAndChatChannelId(USER1.getId(), FRONTEND_CHAT_CHANNEL.getId())
				.orElseThrow();

			// 첫 번째 채널의 세 번째 메시지까지 읽음 처리 (2개 안읽음 상태로 설정)
			ChatChannelMessage thirdMessage = chatChannelMessageRepository
				.findChatChannelMessageByChatChannelAndCriteria(FRONTEND_CHAT_CHANNEL, null,
					PageRequest.of(0, 5))
				.get(2);

			userChatChannel.updateLastReadMessageId(thirdMessage.getId());

			// when
			UnreadMessageCountResponse response = chatChannelService
				.getTeamspaceUnreadMessageCount(USER1_DETAILS, OS_TEAMSPACE.getId());

			// then
			// 예상 결과: 첫 번째 채널에서 2개(5개 중 3개 읽음) + 두 번째 채널에서 3개 = 총 5개 안읽음
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.unreadMessageCount()).isEqualTo(5);
			});
		}

		@Test
		@DisplayName("모든 메시지를 읽은 경우 0을 반환한다")
		void getTeamspaceUnreadCount_AllRead() {
			// given
			// 첫 번째 채널에 메시지 5개 생성
			ChatChannelMessage lastMsg = null;
			for (int i = 0; i < 5; i++) {
				lastMsg = testFixtureBuilder.buildChatChannelMessage(
					CHAT_MESSAGE1(USER2, OS_TEAMSPACE, FRONTEND_CHAT_CHANNEL));
				FRONTEND_CHAT_CHANNEL.updateLastChatMessage(lastMsg.getId());
			}

			// USER1의 모든 메시지를 읽음 표시
			UserChatChannel userChatChannel = userChatChannelRepository
				.findByUserIdAndChatChannelId(USER1.getId(), FRONTEND_CHAT_CHANNEL.getId())
				.orElseThrow();

			userChatChannel.updateLastReadMessageId(lastMsg.getId());

			// when
			UnreadMessageCountResponse response = chatChannelService
				.getTeamspaceUnreadMessageCount(USER1_DETAILS, OS_TEAMSPACE.getId());

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.unreadMessageCount()).isEqualTo(0);
			});
		}

		@Test
		@DisplayName("메시지가 없는 경우 0을 반환한다")
		void getTeamspaceUnreadCount_NoMessages() {
			// when
			UnreadMessageCountResponse response = chatChannelService
				.getTeamspaceUnreadMessageCount(USER1_DETAILS, OS_TEAMSPACE.getId());

			// then
			SoftAssertions.assertSoftly(softly -> {
				softly.assertThat(response).isNotNull();
				softly.assertThat(response.unreadMessageCount()).isEqualTo(0);
			});
		}

		@Test
		@DisplayName("팀스페이스 접근 권한이 없으면 예외가 발생한다")
		void getTeamspaceUnreadCount_Fail_NoAccess() {
			// given
			User OTHER_USER = testFixtureBuilder.buildUser(RANDOMUSER());
			CustomUserDetails OTHER_USER_DETAILS = createCustomUserDetailsByUser(OTHER_USER);

			// when & then
			assertThatThrownBy(() ->
				chatChannelService.getTeamspaceUnreadMessageCount(OTHER_USER_DETAILS, OS_TEAMSPACE.getId()))
				.isExactlyInstanceOf(CommonException.class)
				.hasMessageContaining(ExceptionCode.FORBIDDEN_TEAMSPACE.getMessage());
		}
	}
}
