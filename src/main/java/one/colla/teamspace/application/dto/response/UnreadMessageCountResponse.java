package one.colla.teamspace.application.dto.response;

public record UnreadMessageCountResponse(
	int unreadMessageCount
) {
	public static UnreadMessageCountResponse of(int unreadMessageCount) {
		return new UnreadMessageCountResponse(unreadMessageCount);
	}
}
