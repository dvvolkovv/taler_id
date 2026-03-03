import { Body, Controller, Post, Get, Param, Query, UseGuards, Headers } from "@nestjs/common";
import { VoiceService } from "./voice.service";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";

@Controller("voice")
@UseGuards(JwtAuthGuard)
export class VoiceController {
  constructor(private readonly service: VoiceService) {}

  @Post("rooms")
  createRoom(
    @Body("withAi") withAi: boolean,
    @Body("conversationId") conversationId: string | undefined,
    @CurrentUser() user: any,
    @Headers("authorization") authHeader: string,
  ) {
    const userToken = authHeader ? authHeader.replace("Bearer ", "") : undefined;
    const includeAi = withAi === undefined ? true : withAi;
    return this.service.createRoom(user.sub, includeAi, userToken, conversationId);
  }

  @Post("rooms/:name/join")
  joinRoom(@Param("name") name: string, @CurrentUser() user: any) {
    return this.service.joinRoom(name, user.sub);
  }

  @Post("session")
  createVoiceSession(@CurrentUser() user: any) {
    return this.service.createVoiceSession(user.sub);
  }

  @Get("call-history")
  getCallHistory(
    @CurrentUser() user: any,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    return this.service.getCallHistory(
      user.sub,
      page ? parseInt(page, 10) : 0,
      limit ? parseInt(limit, 10) : 50,
    );
  }
}
