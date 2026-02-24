import { Body, Controller, Post, Param, UseGuards, Headers } from "@nestjs/common";
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
    @CurrentUser() user: any,
    @Headers("authorization") authHeader: string,
  ) {
    const userToken = authHeader ? authHeader.replace("Bearer ", "") : undefined;
    const includeAi = withAi === undefined ? true : withAi;
    return this.service.createRoom(user.sub, includeAi, userToken);
  }

  @Post("rooms/:name/join")
  joinRoom(@Param("name") name: string, @CurrentUser() user: any) {
    return this.service.joinRoom(name, user.sub);
  }

  @Post("session")
  createVoiceSession(@CurrentUser() user: any) {
    return this.service.createVoiceSession(user.sub);
  }
}
