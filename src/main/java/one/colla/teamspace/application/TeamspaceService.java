package one.colla.teamspace.application;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import one.colla.chat.domain.ChatChannel;
import one.colla.chat.domain.ChatChannelMessage;
import one.colla.chat.domain.ChatChannelMessageRepository;
import one.colla.chat.domain.ChatChannelRepository;
import one.colla.chat.domain.UserChatChannel;
import one.colla.chat.domain.UserChatChannelRepository;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.common.util.RandomCodeGenerator;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;
import one.colla.infra.mail.events.InviteCodeSendMailEvent;
import one.colla.infra.redis.invite.InviteCode;
import one.colla.infra.redis.invite.InviteCodeService;
import one.colla.teamspace.application.dto.request.CreateTagRequest;
import one.colla.teamspace.application.dto.request.CreateTeamspaceRequest;
import one.colla.teamspace.application.dto.request.ParticipateRequest;
import one.colla.teamspace.application.dto.request.SendMailInviteCodeRequest;
import one.colla.teamspace.application.dto.request.UpdateTeamspaceSettingsRequest;
import one.colla.teamspace.application.dto.response.CreateTagResponse;
import one.colla.teamspace.application.dto.response.CreateTeamspaceResponse;
import one.colla.teamspace.application.dto.response.InviteCodeResponse;
import one.colla.teamspace.application.dto.response.ParticipantDto;
import one.colla.teamspace.application.dto.response.TeamspaceInfoResponse;
import one.colla.teamspace.application.dto.response.TeamspaceParticipantsResponse;
import one.colla.teamspace.application.dto.response.TeamspaceSettingsResponse;
import one.colla.teamspace.domain.Tag;
import one.colla.teamspace.domain.TagRepository;
import one.colla.teamspace.domain.Teamspace;
import one.colla.teamspace.domain.TeamspaceRepository;
import one.colla.teamspace.domain.TeamspaceRole;
import one.colla.teamspace.domain.UserTeamspace;
import one.colla.teamspace.domain.UserTeamspaceRepository;
import one.colla.teamspace.domain.vo.TagName;
import one.colla.teamspace.domain.vo.TeamspaceName;
import one.colla.teamspace.domain.vo.TeamspaceProfileImageUrl;
import one.colla.user.domain.User;
import one.colla.user.domain.UserRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class TeamspaceService {
	private static final int INVITE_CODE_LENGTH = 10;
	private static final int VALID_HOURS = 72;
	private static final int SECONDS_PER_HOUR = 3_600;
	private static final int MAX_TEAMSPACE_USERS = 10;

	private static final String INITIAL_CHAT_CHANNEL_NAME = "일반";

	private final InviteCodeService inviteCodeService;
	private final TeamspaceRepository teamspaceRepository;
	private final UserTeamspaceRepository userTeamspaceRepository;
	private final UserRepository userRepository;
	private final TagRepository tagRepository;
	private final ApplicationEventPublisher publisher;
	private final RandomCodeGenerator randomCodeGenerator;
	private final UserChatChannelRepository userChatChannelRepository;
	private final ChatChannelRepository chatChannelRepository;
	private final ChatChannelMessageRepository chatChannelMessageRepository;

	@Transactional
	public CreateTeamspaceResponse create(final CustomUserDetails userDetails, final CreateTeamspaceRequest request) {
		final User user = userRepository.findById(userDetails.getUserId())
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_USER));

		final Teamspace createdTeamspace = teamspaceRepository.save(Teamspace.from(request.teamspaceName()));
		final UserTeamspace participatedUserTeamspace = user.participate(createdTeamspace, TeamspaceRole.LEADER);
		final ChatChannel chatChannel = ChatChannel.of(createdTeamspace, INITIAL_CHAT_CHANNEL_NAME);
		final UserChatChannel participatedUserChatChannel = chatChannel.participateTeamspaceUser(
			participatedUserTeamspace);

		chatChannelRepository.save(chatChannel);
		userChatChannelRepository.save(participatedUserChatChannel);
		userTeamspaceRepository.save(participatedUserTeamspace);

		log.info("팀스페이스 생성 - 팀스페이스 Id: {}, 생성한 사용자 Id: {}", createdTeamspace.getId(), user.getId());
		return CreateTeamspaceResponse.from(createdTeamspace);
	}

	@Transactional(readOnly = true)
	public TeamspaceInfoResponse readInfoByCode(@Nullable CustomUserDetails userDetails, String inviteCode) {
		Long teamspaceId = inviteCodeService.getTeamspaceIdByCode(inviteCode);

		User user = null;
		if (userDetails != null) {
			user = userRepository.findById(userDetails.getUserId())
				.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_USER));
		}

		Teamspace teamspace = teamspaceRepository.findById(teamspaceId)
			.orElseThrow(() -> new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE));

		boolean isParticipated = isParticipatedUser(user, teamspace);

		log.info("팀스페이스 정보조회 - 팀스페이스 Id: {}, 조회 사용자 Id: {}", teamspace.getId(), user != null ? user.getId() : "None");

		return TeamspaceInfoResponse.of(isParticipated, teamspace);
	}

	@Transactional
	public InviteCodeResponse getInviteCode(CustomUserDetails userDetails, Long teamspaceId) {
		Pair<InviteCode, UserTeamspace> pair = generateAndSaveInviteCodeByTeamspaceId(userDetails, teamspaceId);
		InviteCode inviteCode = pair.getLeft();

		log.info("초대코드 생성(Copy) - 팀스페이스 Id: {}, 초대코드: {}", teamspaceId, inviteCode.getCode());
		return InviteCodeResponse.from(inviteCode);
	}

	@Transactional
	public void sendInviteCode(CustomUserDetails userDetails, Long teamspaceId, SendMailInviteCodeRequest request) {
		Pair<InviteCode, UserTeamspace> pair = generateAndSaveInviteCodeByTeamspaceId(userDetails, teamspaceId);
		InviteCode inviteCode = pair.getLeft();
		UserTeamspace userTeamspace = pair.getRight();
		String inviterName = userTeamspace.getUser().getUsernameValue();

		Teamspace teamspace = userTeamspace.getTeamspace();
		String teamspaceName = teamspace.getTeamspaceNameValue();
		String teamspaceImageUrl = teamspace.getProfileImageUrlValue();
		Integer numParticipants = teamspace.getUserTeamspaces().size();

		publisher.publishEvent(
			new InviteCodeSendMailEvent(request.email(), teamspaceName, inviterName, inviteCode.getCode(),
				teamspaceImageUrl, numParticipants)
		);

		log.info("초대코드 생성(Mail) - 팀스페이스 Id: {}, 초대코드: {}", teamspaceId, inviteCode.getCode());
	}

	@Transactional
	public void participate(CustomUserDetails userDetails, Long teamspaceId, ParticipateRequest request) {
		final User user = userRepository.findById(userDetails.getUserId())
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_USER));

		final Teamspace teamspace = teamspaceRepository.findById(teamspaceId).orElseThrow(
			() -> new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE)
		);

		if (!Objects.equals(teamspace.getId(), inviteCodeService.getTeamspaceIdByCode(request.inviteCode()))) {
			log.info("팀스페이스 참가 실패(초대코드-팀 불일치) - 팀스페이스 Id: {}, 사용자 Id: {}", teamspaceId, user.getId());
			throw new CommonException(ExceptionCode.INVALID_OR_EXPIRED_INVITATION_CODE);
		}
		if (isParticipatedUser(user, teamspace)) {
			log.info("팀스페이스 참가 실패(이미 참가한 사용자) - 팀스페이스 Id: {}, 사용자 Id: {}", teamspaceId, user.getId());
			throw new CommonException(ExceptionCode.ALREADY_PARTICIPATED);
		}
		if (teamspace.getUserTeamspaces().size() >= MAX_TEAMSPACE_USERS) {
			log.info("팀스페이스 참가 실패(인원 초과) - 팀스페이스 Id: {}, 사용자 Id: {}", teamspaceId, user.getId());
			throw new CommonException(ExceptionCode.TEAMSPACE_FULL);
		}

		final UserTeamspace participatedUserTeamspace = user.participate(teamspace, TeamspaceRole.MEMBER);

		final List<UserChatChannel> participatedUserChatChannels = teamspace.getChatChannels().stream()
			.map(chatChannel -> {
				UserChatChannel userChatChannel = chatChannel.participateTeamspaceUser(participatedUserTeamspace);

				Long latestMessageId = getLatestMessageIdForChannel(chatChannel);

				if (latestMessageId != null) {
					userChatChannel.updateLastReadMessageId(latestMessageId);
				}
				return userChatChannel;
			})
			.toList();

		userTeamspaceRepository.save(participatedUserTeamspace);
		userChatChannelRepository.saveAll(participatedUserChatChannels);
		log.info("팀스페이스 참가 - 팀스페이스 Id: {}, 사용자 Id: {}", teamspaceId, user.getId());
	}

	private Long getLatestMessageIdForChannel(ChatChannel chatChannel) {
		List<ChatChannelMessage> latestMessages = chatChannelMessageRepository
			.findChatChannelMessageByChatChannelAndCriteria(
				chatChannel,
				null,
				Pageable.ofSize(1)
			);

		return latestMessages.isEmpty() ? null : latestMessages.get(0).getId();
	}

	@Transactional(readOnly = true)
	public TeamspaceParticipantsResponse getParticipants(CustomUserDetails userDetails, Long teamspaceId) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);
		Teamspace teamspace = userTeamspace.getTeamspace();

		List<ParticipantDto> participants = getParticipantByTeamspace(teamspace);
		return TeamspaceParticipantsResponse.from(participants);
	}

	@Transactional(readOnly = true)
	public TeamspaceSettingsResponse getSettings(CustomUserDetails userDetails, Long teamspaceId) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);

		if (userTeamspace.getTeamspaceRole() != TeamspaceRole.LEADER) {
			throw new CommonException(ExceptionCode.ONLY_LEADER_ACCESS);
		}

		Teamspace teamspace = userTeamspace.getTeamspace();
		List<ParticipantDto> participants = getParticipantByTeamspace(teamspace);

		return TeamspaceSettingsResponse.of(teamspace, participants);
	}

	@Transactional
	public CreateTagResponse createTag(CustomUserDetails userDetails, Long teamspaceId, CreateTagRequest request) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);

		if (userTeamspace.getTeamspaceRole() != TeamspaceRole.LEADER) {
			throw new CommonException(ExceptionCode.ONLY_LEADER_ACCESS);
		}

		if (tagRepository.existsByTeamspaceAndTagName(userTeamspace.getTeamspace(), TagName.from(request.tagName()))) {
			throw new CommonException(ExceptionCode.CONFLICT_TAGS);
		}

		Tag newTag = Tag.createTagForTeamspace(request.tagName(), userTeamspace.getTeamspace());
		Tag savedTag = tagRepository.save(newTag);

		log.info("새 태그 생성 - 팀스페이스 Id: {}, 사용자 Id: {}, 태그 이름: {}", teamspaceId, userDetails.getUserId(),
			savedTag.getTagNameValue());
		return CreateTagResponse.from(savedTag);
	}

	@Transactional
	public void updateSettings(
		CustomUserDetails userDetails,
		Long teamspaceId,
		UpdateTeamspaceSettingsRequest request
	) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);

		if (userTeamspace.getTeamspaceRole() != TeamspaceRole.LEADER) {
			throw new CommonException(ExceptionCode.ONLY_LEADER_ACCESS);
		}

		Teamspace teamspace = userTeamspace.getTeamspace();

		if (request.name() != null) {
			TeamspaceName teamspaceName = TeamspaceName.from(request.name());
			teamspace.changeTeamspaceName(teamspaceName);
		}

		if (request.profileImageUrl() != null) {
			TeamspaceProfileImageUrl teamspaceProfileImageUrl = new TeamspaceProfileImageUrl(request.profileImageUrl());
			teamspace.changeProfileImageUrl(teamspaceProfileImageUrl);
		}

		if (request.users() != null && !request.users().isEmpty()) {
			List<UpdateTeamspaceSettingsRequest.UserUpdateInfo> willChangeUserTags = request.users();
			List<UserTeamspace> userTeamspaces = teamspace.getUserTeamspaces();

			willChangeUserTags.forEach(userUpdateInfo -> {
				boolean found = userTeamspaces.stream()
					.anyMatch(ut -> Objects.equals(ut.getUser().getId(), userUpdateInfo.id()));

				if (!found) {
					log.info("팀 스페이스 설정 업데이트 실패(팀스페이스 인원이 아님) - 팀 스페이스 Id: {}, 사용자 Id: {}", teamspaceId,
						userDetails.getUserId());
					throw new CommonException(ExceptionCode.FAIL_CHANGE_USERTAG);
				}

				userTeamspaces.stream()
					.filter(ut -> Objects.equals(ut.getUser().getId(), userUpdateInfo.id()))
					.findFirst()
					.ifPresent(ut -> ut.changeTag(tagRepository.findById(userUpdateInfo.tagId())
						.orElseThrow(() -> {
							log.info("팀 스페이스 설정 업데이트 실패(존재하지 않는 태그) - 팀 스페이스 Id: {}, 사용자 Id: {}", teamspaceId,
								userDetails.getUserId());
							return new CommonException(ExceptionCode.FAIL_CHANGE_USERTAG);
						})
					));
			});
		}

		log.info("팀 스페이스 설정 업데이트 - 팀 스페이스 Id: {}, 사용자 Id: {}", teamspaceId, userDetails.getUserId());
	}

	@Transactional
	public void deleteProfileImageUrl(CustomUserDetails userDetails, Long teamspaceId) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);

		if (userTeamspace.getTeamspaceRole() != TeamspaceRole.LEADER) {
			throw new CommonException(ExceptionCode.ONLY_LEADER_ACCESS);
		}

		Teamspace teamspace = userTeamspace.getTeamspace();
		teamspace.deleteProfileImageUrl();

		log.info("팀스페이스 프로필 사진 삭제 완료 - 팀 스페이스 Id: {} 사용자 Id: {}", teamspace, userDetails.getUserId());
	}

	private Pair<InviteCode, UserTeamspace> generateAndSaveInviteCodeByTeamspaceId(CustomUserDetails userDetails,
		Long teamspaceId) {
		UserTeamspace userTeamspace = getUserTeamspace(userDetails, teamspaceId);

		int validSeconds = VALID_HOURS * SECONDS_PER_HOUR;

		String generatedCode = "";
		boolean exists = true;

		do {
			generatedCode = randomCodeGenerator.generateRandomString(INVITE_CODE_LENGTH);
			exists = inviteCodeService.existsByCode(generatedCode);
		} while (exists);

		InviteCode inviteCode = inviteCodeService.saveInviteCode(
			InviteCode.of(generatedCode, userTeamspace.getTeamspace().getId(), validSeconds));

		return Pair.of(inviteCode, userTeamspace);
	}

	@Transactional(readOnly = true)
	public Map<Long, Long> countParticipantsByTeamspaceIds(List<Long> teamspaceIds) {
		return teamspaceRepository.countParticipantsByTeamspaceIds(teamspaceIds).stream()
			.collect(Collectors.toMap(
				arr -> (Long)arr[0],  // 팀스페이스 ID
				arr -> (Long)arr[1]   // 참여자 수
			));
	}

	/**
	 * 현재 사용자가 특정 팀 스페이스의 참가자인지 확인하고, 해당 팀 스페이스에 대한 사용자-팀 매핑 엔티티를 반환합니다.
	 *
	 * @param userDetails 현재 사용자의 상세 정보를 나타내는 객체
	 * @param teamspaceId 조회할 팀 스페이스의 고유 식별자
	 * @return 특정 팀 스페이스에 대한 사용자-팀 매핑 엔티티 ({@link UserTeamspace})
	 * @throws CommonException 현재 사용자가 존재하지 않거나 해당 팀 스페이스의 참가자가 아닐 경우 발생하는 예외
	 *                         (예외 코드: {@link ExceptionCode#NOT_FOUND_USER}, {@link ExceptionCode#FORBIDDEN_TEAMSPACE})
	 */

	public UserTeamspace getUserTeamspace(CustomUserDetails userDetails, Long teamspaceId) {
		final User user = userRepository.findById(userDetails.getUserId())
			.orElseThrow(() -> new CommonException(ExceptionCode.NOT_FOUND_USER));

		UserTeamspace userTeamspace = user.getUserTeamspaces().stream()
			.filter(ut -> ut.getTeamspace().getId().equals(teamspaceId))
			.findFirst()
			.orElseThrow(() -> new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE));

		log.info("사용자 팀스페이스 접근 권한 확인 - 팀스페이스 Id: {}, 사용자 Id: {}", teamspaceId, userDetails.getUserId());
		return userTeamspace;
	}

	private List<ParticipantDto> getParticipantByTeamspace(Teamspace teamspace) {
		List<UserTeamspace> userTeamspaces = teamspace.getUserTeamspaces();
		return userTeamspaces.stream()
			.map(ut -> ParticipantDto.of(ut.getUser(), ut, ut.getTag()))
			.toList();
	}

	private boolean isParticipatedUser(@Nullable User user, Teamspace teamspace) {
		return user != null && userTeamspaceRepository.existsByUserAndTeamspace(user, teamspace);
	}
}

