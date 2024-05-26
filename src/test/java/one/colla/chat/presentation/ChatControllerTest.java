package one.colla.chat.presentation;

import static com.epages.restdocs.apispec.ResourceDocumentation.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.*;
import static org.springframework.restdocs.payload.PayloadDocumentation.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.restdocs.payload.FieldDescriptor;
import org.springframework.test.web.servlet.ResultMatcher;

import com.epages.restdocs.apispec.ResourceSnippetParameters;
import com.epages.restdocs.apispec.Schema;

import one.colla.chat.application.ChatChannelService;
import one.colla.chat.application.dto.request.CreateChatChannelRequest;
import one.colla.chat.application.dto.request.UpdateChatChannelNameRequest;
import one.colla.chat.application.dto.response.ChatChannelInfoDto;
import one.colla.chat.application.dto.response.ChatChannelsResponse;
import one.colla.chat.application.dto.response.CreateChatChannelResponse;
import one.colla.common.ControllerTest;
import one.colla.common.presentation.ApiResponse;
import one.colla.common.security.authentication.CustomUserDetails;
import one.colla.common.security.authentication.WithMockCustomUser;
import one.colla.global.exception.CommonException;
import one.colla.global.exception.ExceptionCode;

@WebMvcTest(ChatController.class)
class ChatControllerTest extends ControllerTest {

	@MockBean
	private ChatChannelService chatChannelService;

	@Nested
	@DisplayName("채팅 채널 생성 문서화")
	class CreateChatChannelDocs {
		final Long teamspaceId = 1L;
		final CreateChatChannelRequest request = new CreateChatChannelRequest("새로운 채팅 채널");
		final CreateChatChannelResponse response = new CreateChatChannelResponse(1L);

		@DisplayName("채팅 채널 생성 성공")
		@WithMockCustomUser
		@Test
		void createChatChannel_Success() throws Exception {

			given(chatChannelService.createChatChannel(any(CustomUserDetails.class), eq(teamspaceId), eq(request)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isCreated(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("chatChannelId").description("생성된 채팅 채널 Id")
				),
				"ApiResponse<CreateChatChannelResponse>"
			);
		}

		@DisplayName("채팅 채널 생성 실패 - 접근 권한이 없거나 존재하지 않는 팀스페이스")
		@WithMockCustomUser
		@Test
		void createChatChannel_Fail() throws Exception {
			willThrow(new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE)).given(chatChannelService)
				.createChatChannel(any(CustomUserDetails.class), eq(teamspaceId), eq(request));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.FORBIDDEN_TEAMSPACE),
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
			mockMvc.perform(
					post("/api/v1/teamspaces/{teamspaceId}/chat-channels", teamspaceId)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
						.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("chatChannel-controller")
						.description("채팅 채널을 생성합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("CreateChatChannelRequest"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());

		}
	}

	@Nested
	@DisplayName("채팅 채널 조회 문서화")
	class GetChatChannelsDocs {
		final Long teamspaceId = 1L;
		final List<ChatChannelInfoDto> chatChannelInfoDtos = List.of(
			new ChatChannelInfoDto(1L, "프론트엔드", "안녕하세요",
				String.valueOf(LocalDateTime.of(2024, 5, 8, 4, 12, 34)))
		);
		final ChatChannelsResponse response = ChatChannelsResponse.from(chatChannelInfoDtos);

		@DisplayName("채팅 채널 조회 성공")
		@WithMockCustomUser
		@Test
		void getChatChannels_Success() throws Exception {

			given(chatChannelService.getChatChannels(any(CustomUserDetails.class), eq(teamspaceId)))
				.willReturn(response);

			doTest(
				ApiResponse.createSuccessResponse(response),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(
					fieldWithPath("chatChannels").description("채팅 채널 목록"),
					fieldWithPath("chatChannels[].id").description("채팅 채널 ID"),
					fieldWithPath("chatChannels[].name").description("채팅 채널 이름"),
					fieldWithPath("chatChannels[].lastChatMessage").description("채팅 채널 마지막 메시지 내용"),
					fieldWithPath("chatChannels[].lastChatCreatedAt").description("채팅 채널 마지막 메시지 생성 시간")
				),
				"ApiResponse<ChatChannelsResponse>"
			);
		}

		@DisplayName("채팅 채널 조회 실패 - 접근 권한이 없거나 존재하지 않는 팀스페이스")
		@WithMockCustomUser
		@Test
		void getChatChannels_Fail() throws Exception {
			willThrow(new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE)).given(chatChannelService)
				.getChatChannels(any(CustomUserDetails.class), eq(teamspaceId));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.FORBIDDEN_TEAMSPACE),
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
			mockMvc.perform(
					get("/api/v1/teamspaces/{teamspaceId}/chat-channels", teamspaceId)
						.with(csrf())
				)
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("chatChannel-controller")
						.description("채팅 채널 목록을 조회합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}
	}

	@Nested
	@DisplayName("채팅 채널 이름 수정 문서화")
	class UpdateChatChannelNameDocs {
		final Long teamspaceId = 1L;
		final UpdateChatChannelNameRequest request = new UpdateChatChannelNameRequest(1L, "수정할 채팅 채널 이름");

		@DisplayName("채팅 채널 이름 수정 성공")
		@WithMockCustomUser
		@Test
		void updateChatChannelName_Success() throws Exception {

			willDoNothing().given(chatChannelService)
				.updateChatChannelName(any(CustomUserDetails.class), eq(teamspaceId), eq(request));

			doTest(
				ApiResponse.createSuccessResponse(Map.of()),
				status().isOk(),
				apiDocHelper.createSuccessResponseFields(),
				"ApiResponse"
			);
		}

		@DisplayName("채팅 채널 이름 수정 실패 - 접근 권한이 없거나 존재하지 않는 팀스페이스 또는 채널")
		@WithMockCustomUser
		@Test
		void updateChatChannelName_Fail() throws Exception {
			willThrow(new CommonException(ExceptionCode.FORBIDDEN_TEAMSPACE)).given(chatChannelService)
				.updateChatChannelName(any(CustomUserDetails.class), eq(teamspaceId), eq(request));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.FORBIDDEN_TEAMSPACE),
				status().isForbidden(),
				apiDocHelper.createErrorResponseFields(),
				"ApiResponse"
			);
		}

		@DisplayName("채팅 채널 이름 수정 실패 - 채널이 존재하지 않음")
		@WithMockCustomUser
		@Test
		void updateChatChannelName_Fail_ChannelNotFound() throws Exception {
			willThrow(new CommonException(ExceptionCode.NOT_FOUND_CHAT_CHANNEL)).given(chatChannelService)
				.updateChatChannelName(any(CustomUserDetails.class), eq(teamspaceId), eq(request));

			doTest(
				ApiResponse.createErrorResponse(ExceptionCode.NOT_FOUND_CHAT_CHANNEL),
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
					patch("/api/v1/teamspaces/{teamspaceId}/chat-channels/name", teamspaceId)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request))
						.with(csrf()))
				.andExpect(statusMatcher)
				.andExpect(content().json(objectMapper.writeValueAsString(response)))
				.andDo(restDocs.document(
					resource(ResourceSnippetParameters.builder()
						.tag("chatChannel-controller")
						.description("채팅 채널 이름을 수정합니다.")
						.pathParameters(
							parameterWithName("teamspaceId").description("팀스페이스 ID")
						)
						.responseFields(responseFields)
						.requestSchema(Schema.schema("UpdateChatChannelNameRequest"))
						.responseSchema(Schema.schema(responseSchemaTitle))
						.build()
					)
				)).andDo(print());
		}
	}

}
