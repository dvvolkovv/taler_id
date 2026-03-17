import { Body, Controller, Post, Get, Delete, Param, Query, UseGuards, Headers } from "@nestjs/common";
import { VoiceService } from "./voice.service";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";

@Controller("voice")
export class VoiceController {
  constructor(private readonly service: VoiceService) {}

  @Post("rooms")
  @UseGuards(JwtAuthGuard)
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

  @Get("rooms/my")
  @UseGuards(JwtAuthGuard)
  getMyRoom(@CurrentUser() user: any) {
    return this.service.getOrCreatePersonalRoom(user.sub);
  }

  @Post("rooms/temporary")
  @UseGuards(JwtAuthGuard)
  createTemporaryRoom(
    @Body("title") title: string | undefined,
    @Body("password") password: string | undefined,
    @CurrentUser() user: any,
  ) {
    return this.service.createTemporaryRoom(user.sub, title, password);
  }

  @Delete("rooms/temporary/:code")
  @UseGuards(JwtAuthGuard)
  deactivateTemporaryRoom(
    @Param("code") code: string,
    @CurrentUser() user: any,
  ) {
    return this.service.deactivateTemporaryRoom(code, user.sub);
  }

  @Post("rooms/public")
  @UseGuards(JwtAuthGuard)
  createPublicRoom(
    @Body("title") title: string | undefined,
    @Body("password") password: string | undefined,
    @CurrentUser() user: any,
  ) {
    return this.service.createPublicRoom(user.sub, title, password);
  }

  @Get("rooms/public/:code")
  getPublicRoom(@Param("code") code: string) {
    return this.service.getPublicRoom(code);
  }

  @Post("rooms/public/:code/join")
  joinPublicRoom(
    @Param("code") code: string,
    @Body("name") name: string,
    @Body("password") password: string | undefined,
  ) {
    return this.service.joinPublicRoom(code, name || "Guest", password);
  }

  @Post("rooms/public/:code/join-auth")
  @UseGuards(JwtAuthGuard)
  joinPublicRoomAuth(
    @Param("code") code: string,
    @Body("password") password: string | undefined,
    @CurrentUser() user: any,
  ) {
    return this.service.joinPublicRoomAuth(code, user.sub, password);
  }

  @Post("rooms/:name/join")
  @UseGuards(JwtAuthGuard)
  joinRoom(@Param("name") name: string, @CurrentUser() user: any) {
    return this.service.joinRoom(name, user.sub);
  }

  @Post("session")
  @UseGuards(JwtAuthGuard)
  createVoiceSession(@CurrentUser() user: any) {
    return this.service.createVoiceSession(user.sub);
  }

  @Get("call-history")
  @UseGuards(JwtAuthGuard)
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


  @Get("call-history/:id")
  @UseGuards(JwtAuthGuard)
  getCallDetail(
    @Param("id") id: string,
    @CurrentUser() user: any,
  ) {
    return this.service.getCallDetail(id, user.sub);
  }

  // ─── Meeting Recorder (no auth — protected by roomName UUID) ───

  @Post("rooms/:roomName/recorder/start")
  startRecorder(@Param("roomName") roomName: string, @Body() body: any) {
    return this.service.startRecorder(roomName, body?.withAi !== false);
  }

  @Post("rooms/:roomName/recorder/stop")
  stopRecorder(@Param("roomName") roomName: string) {
    return this.service.stopRecorder(roomName);
  }

  @Get("rooms/:roomName/recorder/status")
  getRecorderStatus(@Param("roomName") roomName: string) {
    return this.service.getRecorderStatus(roomName);
  }

  // ─── Voice Translator ───

  @Get("translator/languages")
  getTranslatorLanguages() {
    return this.service.getTranslatorLanguages();
  }

  @Post("rooms/:roomName/translator/start")
  @UseGuards(JwtAuthGuard)
  startTranslator(@Param("roomName") roomName: string) {
    return this.service.startTranslator(roomName);
  }

  @Post("rooms/:roomName/translator/stop")
  @UseGuards(JwtAuthGuard)
  stopTranslator(@Param("roomName") roomName: string) {
    return this.service.stopTranslator(roomName);
  }

  @Post("rooms/:roomName/set-lang")
  @UseGuards(JwtAuthGuard)
  setTranslatorLang(
    @Param("roomName") roomName: string,
    @Body("lang") lang: string,
    @CurrentUser() user: any,
  ) {
    return this.service.setTranslatorLang(roomName, user.sub, lang);
  }

  @Get("rooms/:roomName/translator/status")
  getTranslatorStatus(@Param("roomName") roomName: string) {
    return this.service.getTranslatorStatus(roomName);
  }

  // ─── Public Translator (no auth — protected by roomName UUID) ───

  @Post("rooms/:roomName/translator/public/start")
  startTranslatorPublic(@Param("roomName") roomName: string) {
    return this.service.startTranslator(roomName);
  }

  @Post("rooms/:roomName/translator/public/stop")
  stopTranslatorPublic(@Param("roomName") roomName: string) {
    return this.service.stopTranslator(roomName);
  }

  @Post("rooms/:roomName/set-lang-public")
  setTranslatorLangPublic(
    @Param("roomName") roomName: string,
    @Body("identity") identity: string,
    @Body("lang") lang: string,
  ) {
    return this.service.setTranslatorLangByIdentity(roomName, identity, lang);
  }

  // ─── Meeting Summaries ───

  @Post("meetings/save")
  saveMeetingSummary(@Body() data: any) {
    return this.service.saveMeetingSummary(data);
  }

  @Get("meetings")
  @UseGuards(JwtAuthGuard)
  getMeetingSummaries(
    @CurrentUser() user: any,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    return this.service.getMeetingSummaries(
      user.sub,
      page ? parseInt(page, 10) : 0,
      limit ? parseInt(limit, 10) : 20,
    );
  }

  @Get("meetings/shared/:id")
  getSharedMeetingSummary(@Param("id") id: string) {
    return this.service.getMeetingSummary(id);
  }

  @Get("meetings/:id")
  @UseGuards(JwtAuthGuard)
  getMeetingSummary(@Param("id") id: string) {
    return this.service.getMeetingSummary(id);
  }

  // ─── Meeting Recordings ───

  @Get("recordings")
  @UseGuards(JwtAuthGuard)
  getMeetingRecordings(
    @CurrentUser() user: any,
    @Query("page") page?: string,
    @Query("limit") limit?: string,
  ) {
    return this.service.getMeetingRecordings(
      user.sub,
      page ? parseInt(page, 10) : 0,
      limit ? parseInt(limit, 10) : 20,
    );
  }
}
