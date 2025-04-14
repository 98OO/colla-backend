package one.colla.teamspace.presentation;

import static com.epages.restdocs.apispec.ResourceDocumentation.*;
import static org.mockito.BDDMockito.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.restdocs.payload.JsonFieldType;
import org.springframework.test.web.servlet.ResultMatcher;

import com.epages.restdocs.apispec.ResourceSnippetParameters;
import com.epages.restdocs.apispec.Schema;

import one.colla.chat.application.ChatChannelService;
import one.colla.common.ControllerTest;
import one.colla.common.presentation.ApiResponse;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.common.security.authentication.WithMockCustomUser;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;
import one.colla.teamspace.application.TeamspaceService;
import one.colla.teamspace.application.dto.request.CreateTagRequest;
import one.colla.teamspace.application.dto.request.CreateTeamspaceRequest;
import one.colla.teamspace.application.dto.request.ParticipateRequest;
import one.colla.teamspace.application.dto.request.SendMailInviteCodeRequest;
import one.colla.teamspace.application.dto.request.UpdateTeamspaceSettingsRequest;
import one.colla.teamspace.application.dto.response.CreateTagResponse;
import one.colla.teamspace.application.dto.response.CreateTeamspaceResponse;
import one.colla.teamspace.application.dto.response.InviteCodeResponse;
import one.colla.teamspace.application.dto.response.ParticipantDto;
import one.colla.teamspace.application.dto.response.TagDto;
import one.colla.teamspace.application.dto.response.TeamspaceInfoResponse;
import one.colla.teamspace.application.dto.response.TeamspaceParticipantsResponse;
import one.colla.teamspace.application.dto.response.TeamspaceSettingsResponse;
import one.colla.teamspace.application.dto.response.UnreadMessageCountResponse;

@WebMvcTest(TeamspaceController.class)
class TeamspaceControllerTest extends ControllerTest {

	@MockBean
	private TeamspaceService teamspaceService;

	@MockBean
	private ChatChannelService chatChannelService;

	@Nested
	@DisplayName("팀스페이스 생성 문서화")
	class CreateTeamspaceDocs {
		final CreateTeamspaceRequest request = new CreateTeamspaceRequest("New Teamspace");
		final CreateTeamspaceResponse response = new CreateTeamspaceResponse(1L);

		@DisplayName("팀스페이스 생성 성공")
		@WithMockCustomUser
		@Test
		void createTeamspaceSuccessfully() throws Exception {
			given(teamspaceService.create(any(CustomUserDetails.class), any(CreateTeamspaceRequest.class)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("teamspaceId").description("생성된 팀스페이스의 ID")
				),
				"ApiResponse<CreateTeamspaceResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {

			mockMvc.perform(
					post("/api/v1/teamspaces").with(csrf())
						.content(objectMapper.writeValueAsString(request))
						.contentType(MediaType.APPLICATION_JSON))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("팀스페이스를 생성합니다.")
						.requestFields(
							fieldWithPath("teamspaceName").description("팀스페이스의 이름").type(JsonFieldType.STRING)
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("CreateTeamspaceRequest"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}

	}

	@Nested
	@DisplayName("팀스페이스 정보 조회 문서화")
	class ReadTeamspaceInfoDocs {
		final String code = "12345";
		final TeamspaceInfoResponse response = new TeamspaceInfoResponse(1L,
			"My Teamspace", "https://example.com", true);

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 정보 조회 성공")
		void readTeamspaceInfoSuccessfully() throws Exception {
			given(teamspaceService.readInfoByCode(any(CustomUserDetails.class), eq(code)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("teamspaceId").description("팀스페이스 ID").type(JsonFieldType.NUMBER),
					fieldWithPath("teamspaceName").description("팀스페이스 이름").type(JsonFieldType.STRING),
					fieldWithPath("teamspaceProfileImageUrl").description("팀스페이스 프로필 이미지 URL")
						.type(JsonFieldType.STRING),
					fieldWithPath("isParticipated").description("참여 상태").type(JsonFieldType.BOOLEAN)
				),
				"ApiResponse<TeamspaceInfoResponse>"
			);
		}

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 정보 조회 실패 - 접근 권한이 없거나 존재하지 않는 팀스페이스")
		void readTeamspaceInfoFailure1() throws Exception {
			given(teamspaceService.readInfoByCode(any(CustomUserDetails.class), eq(code)))
				.willThrow(new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.FORBIDDEN_TEAMSPACE),
				status().isForbidden(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 정보 조회 실패 - 유효하지 않거나 만료된 초대코드")
		void readTeamspaceInfoFailure2() throws Exception {
			given(teamspaceService.readInfoByCode(any(CustomUserDetails.class), eq(code)))
				.willThrow(new CommonException(ExceptionCode.INVALID_OR_EXPIRED_INVITATION_CODE));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.INVALID_OR_EXPIRED_INVITATION_CODE),
				status().isNotFound(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(
					get("/api/v1/teamspaces")
						.queryParam("code", code)
						.with(csrf())
						.accept(MediaType.APPLICATION_JSON))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("초대 코드에 해당하는 특정 팀스페이스의 개요 정보를 불러옵니다.")
						.queryParameters(
							parameterWithName("code").description("팀스페이스 고유 코드")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 초대 코드 발급 문서화")
	class IssueInviteCodeDocs {
		Long teamspaceId = 1L;
		InviteCodeResponse inviteCodeResponse = new InviteCodeResponse("a1B2c3D4e5");

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 초대 코드 발급 성공")
		void issueTeamspaceInviteCodeSuccessfully() throws Exception {
			given(teamspaceService.getInviteCode(any(CustomUserDetails.class), any(Long.class)))
				.willReturn(inviteCodeResponse);

			doTest(
				ApiResponse.createSuccessResponse(inviteCodeResponse),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("inviteCode").description("발급된 초대 코드")
				),
				"ApiResponse<InviteCodeResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(
					post("/api/v1/teamspaces/{teamspaceId}/invitations", teamspaceId)
						.with(csrf())
						.content(objectMapper.writeValueAsString(Map.of()))
						.accept(MediaType.APPLICATION_JSON)
				)
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스의 초대 코드를 발급합니다. (POST 이지만 본문을 담지 말 것)")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("Empty"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 초대 코드 이메일 발송 문서화")
	class SendInviteCodeEmailDocs {
		Long teamspaceId = 1L;
		SendMailInviteCodeRequest request = new SendMailInviteCodeRequest("user@example.com");

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 초대 코드 이메일 발송 성공")
		void sendInviteCodeEmailSuccessfully() throws Exception {
			doNothing().when(teamspaceService).sendInviteCode(any(CustomUserDetails.class), eq(teamspaceId), any(
				SendMailInviteCodeRequest.class));

			doTest(
				ApiResponse.createSuccessResponse(Map.of()),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(),
				"ApiResponse"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(post("/api/v1/teamspaces/{teamspaceId}/invitations/mails", teamspaceId)
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(request))
					.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스의 초대 링크를 이메일로 전송합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.requestFields(
							fieldWithPath("email").description("초대 링크를 보낼 이메일")
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("SendMailInviteCodeRequest"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 참여 문서화")
	class ParticipateTeamspaceDocs {
		Long teamspaceId = 1L;
		ParticipateRequest request = new ParticipateRequest("a1B2c3D4e5");

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 참여 성공")
		void participateTeamspaceSuccessfully() throws Exception {
			doNothing().when(teamspaceService).participate(any(CustomUserDetails.class), eq(teamspaceId), any(
				ParticipateRequest.class));

			doTest(
				ApiResponse.createSuccessResponse(Map.of()),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(),
				"ApiResponse"
			);
		}

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 참여 실패 - 유효하지 않거나 만료된 초대코드")
		void participateTeamspaceFailure1() throws Exception {
			doThrow(new CommonException(ExceptionCode.INVALID_OR_EXPIRED_INVITATION_CODE)).when(teamspaceService)
				.participate(any(CustomUserDetails.class), eq(teamspaceId), any(
					ParticipateRequest.class));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.INVALID_OR_EXPIRED_INVITATION_CODE),
				status().isNotFound(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 참여 실패 - 팀스페이스 인원이 가득 참")
		void participateTeamspaceFailure2() throws Exception {
			doThrow(new CommonException(ExceptionCode.TEAMSPACE_FULL)).when(teamspaceService)
				.participate(any(CustomUserDetails.class), eq(teamspaceId), any(
					ParticipateRequest.class));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.TEAMSPACE_FULL),
				status().isForbidden(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(post("/api/v1/teamspaces/{teamspaceId}/users", teamspaceId)
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(request))
					.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("초대 코드를 통해 특정 팀스페이스에 참가합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.requestFields(
							fieldWithPath("inviteCode").description("초대 코드")
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("ParticipateRequest"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				));
		}
	}

	@Nested
	@DisplayName("팀스페이스 참가자 목록 조회 문서화")
	class GetTeamspaceParticipantsDocs {
		Long teamspaceId = 1L;
		TeamspaceParticipantsResponse participantsResponse = new TeamspaceParticipantsResponse(
			List.of(
				ParticipantDto.builder()
					.id(1L)
					.profileImageUrl("https://example.com")
					.role("LEADER")
					.username("사용자이름")
					.email("example@example.com")
					.tag(new TagDto(1L, "프론트엔드"))
					.build()
			)
		);

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 참가자 목록 조회 성공")
		void getTeamspaceParticipantsSuccessfully() throws Exception {
			given(teamspaceService.getParticipants(any(CustomUserDetails.class), eq(teamspaceId)))
				.willReturn(participantsResponse);

			doTest(
				ApiResponse.createSuccessResponse(participantsResponse),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("users").description("팀스페이스 참가자 목록"),
					fieldWithPath("users[0].id").description("참가자 ID"),
					fieldWithPath("users[0].profileImageUrl").description("참가자 프로필 사진"),
					fieldWithPath("users[0].username").description("참가자 username"),
					fieldWithPath("users[0].email").description("참가자 이메일"),
					fieldWithPath("users[0].role").description("팀스페이스 내 참가자 역할"),
					fieldWithPath("users[0].tag").description("참가자 태그"),
					fieldWithPath("users[0].tag.id").description("참가자 태그 id"),
					fieldWithPath("users[0].tag.name").description("참가자 태그명")
				),
				"ApiResponse<TeamspaceParticipantsResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(get("/api/v1/teamspaces/{teamspaceId}/users", teamspaceId)
					.with(csrf())
					.contentType(MediaType.APPLICATION_JSON))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스 내의 참가자 정보를 불러옵니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					))
				)
				.andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 설정 조회 문서화")
	class GetTeamspaceSettingsDocs {
		Long teamspaceId = 1L;
		TeamspaceSettingsResponse settingsResponse = new TeamspaceSettingsResponse(
			"https://example.com/image.jpg", "Example Teamspace", List.of(new TagDto(1L, "Developer")), List.of(
			new ParticipantDto(1L, "https://example.com/profile.jpg", "username1", "user1@example.com", "Admin",
				new TagDto(1L, "Developer")))
		);

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 설정 조회 성공")
		void getTeamspaceSettingsSuccessfully() throws Exception {
			given(teamspaceService.getSettings(any(CustomUserDetails.class), eq(teamspaceId)))
				.willReturn(settingsResponse);

			doTest(
				ApiResponse.createSuccessResponse(settingsResponse),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("profileImageUrl").description("팀스페이스 프로필 이미지 URL")
						.type(JsonFieldType.STRING),
					fieldWithPath("name").description("팀스페이스 이름").type(JsonFieldType.STRING),
					fieldWithPath("tags[].id").description("각 태그의 ID").type(JsonFieldType.NUMBER),
					fieldWithPath("tags[].name").description("각 태그의 이름").type(JsonFieldType.STRING),
					fieldWithPath("users[].id").description("각 참가자의 ID")
						.type(JsonFieldType.NUMBER),
					fieldWithPath("users[].profileImageUrl").description("각 참가자의 프로필 이미지 URL")
						.type(JsonFieldType.STRING),
					fieldWithPath("users[].username").description("각 참가자의 사용자 이름")
						.type(JsonFieldType.STRING),
					fieldWithPath("users[].email").description("각 참가자의 이메일")
						.type(JsonFieldType.STRING),
					fieldWithPath("users[].role").description("각 참가자의 역할")
						.type(JsonFieldType.STRING),
					fieldWithPath("users[].tag.id").description("각 참가자에 연결된 태그의 ID")
						.type(JsonFieldType.NUMBER),
					fieldWithPath("users[].tag.name").description("각 참가자에 연결된 태그의 이름")
						.type(JsonFieldType.STRING)
				),
				"ApiResponse<TeamspaceSettingsResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(get("/api/v1/teamspaces/{teamspaceId}/settings", teamspaceId)
					.with(csrf())
					.accept(MediaType.APPLICATION_JSON))
				.andExpect(statusMatcher)
				.andExpect(content().json(
					objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스 내의 설정 정보를 불러옵니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)))
				.andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 태그 생성 문서화")
	class CreateTeamspaceTagDocs {
		Long teamspaceId = 1L;
		CreateTagRequest request = new CreateTagRequest("Developer");
		CreateTagResponse response = new CreateTagResponse(new TagDto(1L, "Developer"));

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 태그 생성 성공")
		void createTeamspaceTagSuccessfully() throws Exception {
			given(
				teamspaceService.createTag(any(CustomUserDetails.class), eq(teamspaceId), any(CreateTagRequest.class)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("tag.id").description("생성된 태그의 ID").type(JsonFieldType.NUMBER),
					fieldWithPath("tag.name").description("생성된 태그의 이름").type(JsonFieldType.STRING)
				),
				"ApiResponse<CreateTagResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(post("/api/v1/teamspaces/{teamspaceId}/tags", teamspaceId)
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(request))
					.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스 내에서 새로운 태그를 생성합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스의 고유 식별자")
						)
						.requestFields(
							fieldWithPath("tagName").description("생성할 태그의 이름").type(JsonFieldType.STRING)
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)))
				.andDo(print());

		}
	}

	@Nested
	@DisplayName("팀스페이스 설정 수정 문서화")
	class UpdateTeamspaceSettingsDocs {
		Long teamspaceId = 1L;
		UpdateTeamspaceSettingsRequest request =
			new UpdateTeamspaceSettingsRequest("https://example.com/image.jpg", "Example Teamspace",
				List.of(new UpdateTeamspaceSettingsRequest.UserUpdateInfo(1L, 2L)));

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 설정 수정 성공")
		void updateTeamspaceSettingsSuccessfully() throws Exception {
			doNothing().when(teamspaceService).updateSettings(any(CustomUserDetails.class), eq(teamspaceId),
				any(UpdateTeamspaceSettingsRequest.class));

			doTest(
				ApiResponse.createSuccessResponse(Map.of()),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(),
				"ApiResponse"
			);
		}

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 설정 수정 실패 - 사용자 역할 수정 실패")
		void updateTeamspaceSettingsFailure() throws Exception {
			doThrow(new CommonException(ExceptionCode.FAIL_CHANGE_USERTAG)).when(teamspaceService)
				.updateSettings(any(CustomUserDetails.class), eq(teamspaceId),
					any(UpdateTeamspaceSettingsRequest.class));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.FAIL_CHANGE_USERTAG),
				status().isNotFound(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(patch("/api/v1/teamspaces/{teamspaceId}/settings", teamspaceId)
					.contentType(MediaType.APPLICATION_JSON)
					.content(objectMapper.writeValueAsString(request))
					.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스의 설정을 수정합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스의 고유 식별자")
						)
						.requestFields(
							fieldWithPath("profileImageUrl").description("변경할 팀스페이스 프로필 이미지 Url(선택)")
								.type(JsonFieldType.STRING),
							fieldWithPath("name").description("변경할 팀스페이스명(선택)").type(JsonFieldType.STRING),
							fieldWithPath("users").description("팀스페이스 참가자 태그 변경 목록").type(JsonFieldType.ARRAY),
							fieldWithPath("users[0].id").description("태그를 변경할 사용자 Id").type(JsonFieldType.NUMBER),
							fieldWithPath("users[0].tagId").description("변경할 대상 태그 Id").type(JsonFieldType.NUMBER)
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)))
				.andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 프로필 사진 삭제 문서화")
	class DeleteTeamspaceProfileImageUrlDocs {
		Long teamspaceId = 1L;

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 설정 수정 성공")
		void updateTeamspaceSettingsSuccessfully() throws Exception {
			doNothing().when(teamspaceService).deleteProfileImageUrl(any(CustomUserDetails.class), eq(teamspaceId));

			doTest(
				ApiResponse.createSuccessResponse(Map.of()),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(),
				"ApiResponse"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(delete("/api/v1/teamspaces/{teamspaceId}/settings/profile-image", teamspaceId)
					.contentType(MediaType.APPLICATION_JSON)
					.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스의 프로필 사진을 삭제합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스의 고유 식별자")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)))
				.andDo(print());
		}
	}

	@Nested
	@DisplayName("팀스페이스 안읽은 메시지 개수 조회 문서화")
	class GetTeamspaceUnreadCountDocs {
		Long teamspaceId = 1L;
		UnreadMessageCountResponse response = new UnreadMessageCountResponse(5);

		@Test
		@WithMockCustomUser
		@DisplayName("팀스페이스 안읽은 메시지 개수 조회 성공")
		void getTeamspaceUnreadMessageCountSuccessfully() throws Exception {
			given(chatChannelService.getTeamspaceUnreadMessageCount(any(CustomUserDetails.class), eq(teamspaceId)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("unreadMessageCount").description("안읽은 메시지 개수").type(JsonFieldType.NUMBER)
				),
				"ApiResponse<UnreadMessageCountResponse>"
			);
		}

		private void doTest(
			ApiResponse<?> response,
			ResultMatcher statusMatcher,
			FieldDescriptor[] responseFields,
			String responseSchemaTitle
		) throws Exception {
			mockMvc.perform(get("/api/v1/teamspaces/{teamspaceId}/unread-count", teamspaceId)
					.with(csrf())
					.accept(MediaType.APPLICATION_JSON))
				.andExpect(statusMatcher)
				.andExpect(content().json(
					objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("teamspace-controller")
						.description("특정 팀스페이스 내의 안읽은 메시지 개수를 조회합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)))
				.andDo(print());
		}
	}
}
