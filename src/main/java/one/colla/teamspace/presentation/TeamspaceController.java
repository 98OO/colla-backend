package one.colla.teamspace.presentation;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import one.colla.chat.application.ChatChannelService;
import one.colla.common.presentation.ApiResponse;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.teamspace.application.TeamspaceService;
import one.colla.teamspace.application.dto.request.CreateTagRequest;
import one.colla.teamspace.application.dto.request.CreateTeamspaceRequest;
import one.colla.teamspace.application.dto.request.ParticipateRequest;
import one.colla.teamspace.application.dto.request.SendMailInviteCodeRequest;
import one.colla.teamspace.application.dto.request.UpdateTeamspaceSettingsRequest;
import one.colla.teamspace.application.dto.response.CreateTagResponse;
import one.colla.teamspace.application.dto.response.CreateTeamspaceResponse;
import one.colla.teamspace.application.dto.response.InviteCodeResponse;
import one.colla.teamspace.application.dto.response.TeamspaceInfoResponse;
import one.colla.teamspace.application.dto.response.TeamspaceParticipantsResponse;
import one.colla.teamspace.application.dto.response.TeamspaceSettingsResponse;
import one.colla.teamspace.application.dto.response.UnreadMessageCountResponse;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/teamspaces")
public class TeamspaceController {
	private final TeamspaceService teamspaceService;
	private final ChatChannelService chatChannelService;

	@PostMapping
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<CreateTeamspaceResponse>> createTeamspace(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@RequestBody @Valid final CreateTeamspaceRequest request) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.create(userDetails, request))
		);
	}

	@GetMapping
	public ResponseEntity<ApiResponse<TeamspaceInfoResponse>> readTeamspaceInfo(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@RequestParam(required = true) final String code
	) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.readInfoByCode(userDetails, code))
		);
	}

	@PostMapping("/{teamspaceId}/invitations")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<InviteCodeResponse>> getTeamspaceInviteCode(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId
	) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.getInviteCode(userDetails, teamspaceId))
		);
	}

	@PostMapping("/{teamspaceId}/invitations/mails")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<?>> sendTeamspaceInviteCode(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId,
		@RequestBody @Valid final SendMailInviteCodeRequest request
	) {
		teamspaceService.sendInviteCode(userDetails, teamspaceId, request);

		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(Map.of())
		);
	}

	@PostMapping("/{teamspaceId}/users")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<?>> participateTeamspace(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId,
		@RequestBody @Valid final ParticipateRequest request
	) {
		teamspaceService.participate(userDetails, teamspaceId, request);

		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(Map.of())
		);
	}

	@GetMapping("/{teamspaceId}/users")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<TeamspaceParticipantsResponse>> getTeamspaceParticipants(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId
	) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.getParticipants(userDetails, teamspaceId))
		);
	}

	@GetMapping("/{teamspaceId}/settings")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<TeamspaceSettingsResponse>> getTeamspaceSettings(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId
	) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.getSettings(userDetails, teamspaceId))
		);
	}

	@PostMapping("/{teamspaceId}/tags")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<CreateTagResponse>> createTeamspaceTag(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId,
		@RequestBody @Valid final CreateTagRequest request
	) {
		return ResponseEntity.ok().body(
			ApiResponse.createSuccessResponse(teamspaceService.createTag(userDetails, teamspaceId, request))
		);
	}

	@PatchMapping("/{teamspaceId}/settings")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<?>> updateTeamspaceSettings(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId,
		@RequestBody @Valid final UpdateTeamspaceSettingsRequest request
	) {
		teamspaceService.updateSettings(userDetails, teamspaceId, request);
		return ResponseEntity.ok().body(ApiResponse.createSuccessResponse(Map.of()));
	}

	@DeleteMapping("/{teamspaceId}/settings/profile-image")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<Object>> deleteTeamspaceProfileImageUrl(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId
	) {
		teamspaceService.deleteProfileImageUrl(userDetails, teamspaceId);
		return ResponseEntity.ok().body(ApiResponse.createSuccessResponse(Map.of()));
	}

	@GetMapping("/{teamspaceId}/unread-count")
	@PreAuthorize("isAuthenticated()")
	public ResponseEntity<ApiResponse<UnreadMessageCountResponse>> getTeamspaceUnreadMessageCount(
		@AuthenticationPrincipal final CustomUserDetails userDetails,
		@PathVariable final Long teamspaceId
	) {
		return ResponseEntity.ok()
			.body(ApiResponse.createSuccessResponse(
				chatChannelService.getTeamspaceUnreadMessageCount(userDetails, teamspaceId))
			);
	}
}
