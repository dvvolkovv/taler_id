import { Body, Controller, Post, Get, Delete, Param, Query, UseGuards, UseFilters, Headers, UseInterceptors, UploadedFile, HttpException, HttpStatus } from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";
import { VoiceService } from "./voice.service";
import { JwtAuthGuard } from "../common/guards/jwt-auth.guard";
import { CurrentUser } from "../common/decorators/current-user.decorator";
import { FileStorageService } from "../common/file-storage.service";
import { BillingExceptionFilter } from "../billing/filters/billing-exception.filter";
import { GatingService } from "../billing/services/gating.service";
import { MeteringService } from "../billing/services/metering.service";

@Controller("voice")
export class VoiceController {
  constructor(
    private readonly service: VoiceService,
    private readonly fileStorage: FileStorageService,
    private readonly gating: GatingService,
    private readonly metering: MeteringService,
  ) {}

  @Post("rooms")
  @UseGuards(JwtAuthGuard)
  createRoom(
    @Body("withAi") withAi: boolean,
    @Body("conversationId") conversationId: string | undefined,
    @CurrentUser() user: any,
    @Headers("authorization") authHeader: string,
  ) {
    const userToken = authHeader ? authHeader.replace("Bearer ", "") : undefined;
    // Default to NO ai assistant for regular person-to-person calls. Clients
    // that actually want the gpt-realtime assistant in the room (assistant
    // screen, etc.) already pass withAi:true explicitly. This prevents the
    // old livekit-ai-agent from colliding with the new ai-twin-agent.
    const includeAi = withAi === true;
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
  @UseFilters(BillingExceptionFilter)
  createVoiceSession(@CurrentUser() user: any) {
    return this.service.createVoiceSession(user.sub);
  }

  @Post("session/:sessionId/close")
  @UseGuards(JwtAuthGuard)
  @UseFilters(BillingExceptionFilter)
  async closeVoiceSession(
    @CurrentUser() user: any,
    @Param("sessionId") sessionId: string,
    @Body() body: { durationSec: number },
  ) {
    const rawDuration = (body as { durationSec?: unknown })?.durationSec;
    const durationSec =
      typeof rawDuration === "number" && Number.isFinite(rawDuration) && rawDuration >= 0
        ? rawDuration
        : 0;
    await this.service.closeVoiceSession(user.sub, sessionId, durationSec);
    return { ok: true };
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

  /**
   * Called by the Python ai-twin-agent after a call session with the AI
   * voice twin ends. Saves the full transcript + GPT-generated summary
   * onto the CallLog so the owner can see what the caller wanted while
   * they were away.
   *
   * Protected by a shared secret header instead of JWT because the
   * agent isn't a human user. The secret lives in AI_TWIN_CALLBACK_SECRET
   * on both the backend and the agent .env.
   */
  @Post("ai-twin/callback")
  async aiTwinCallback(
    @Headers("x-ai-twin-secret") secret: string,
    @Body() body: {
      roomName: string;
      transcript: unknown;
      summary: string;
      // Task 14: agent reports the billing session it was dispatched with
      // and the call duration in minutes so we can adjust the final debit.
      billingSessionId?: string;
      units?: number;
    },
  ) {
    const expected = process.env.AI_TWIN_CALLBACK_SECRET;
    if (!expected) {
      throw new HttpException(
        "AI twin callback not configured on server",
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }
    if (!secret || secret !== expected) {
      throw new HttpException("Invalid secret", HttpStatus.UNAUTHORIZED);
    }
    if (!body?.roomName) {
      throw new HttpException("roomName required", HttpStatus.BAD_REQUEST);
    }
    await this.service.saveAiTwinCallData(
      body.roomName,
      body.transcript ?? null,
      body.summary ?? "",
    );

    // Finalize billing: agent's reported duration is authoritative over the
    // cron estimate. reportUsage debits any positive diff; endSession flips
    // status to 'completed'. If the session was already ended by takeoverCall
    // (human picked up mid-call), reportUsage still works — it does not
    // require an active session.
    if (
      body.billingSessionId &&
      typeof body.units === "number" &&
      Number.isFinite(body.units) &&
      body.units >= 0
    ) {
      try {
        await this.metering.reportUsage(
          body.billingSessionId,
          body.units,
          "ai-twin-agent",
        );
      } catch (_) {
        // reportUsage throws on unknown sessionId — swallow to keep the
        // agent callback idempotent. The core transcript save already succeeded.
      }
      await this.gating
        .endSession(body.billingSessionId, "completed")
        .catch(() => {});
    }

    return { ok: true };
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

  // ─── E2EE ───

  @Post("rooms/:roomName/disable-e2ee")
  @UseGuards(JwtAuthGuard)
  disableE2EE(@Param("roomName") roomName: string) {
    return this.service.disableE2EE(roomName);
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
    @Body("sourceLang") sourceLang: string,
    @CurrentUser() user: any,
  ) {
    return this.service.setTranslatorLang(roomName, user.sub, lang, sourceLang);
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
    @Body("sourceLang") sourceLang: string,
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

  // ─── Recording Upload (S3) ───

  @Post("recordings/upload")
  @UseInterceptors(FileInterceptor("file"))
  async uploadRecording(@UploadedFile() file: any) {
    const key = `recordings/${Date.now()}-${file.originalname}`;
    await this.fileStorage.upload(key, file.buffer, file.mimetype || "audio/mpeg");
    const url = this.fileStorage.getPublicUrl(key);
    return { url, key };
  }

  // ─── Post-hoc Transcription ───

  @Post("recordings/:id/transcribe")
  @UseGuards(JwtAuthGuard)
  @UseFilters(BillingExceptionFilter)
  async transcribeRecording(@Param("id") id: string, @CurrentUser() user: any) {
    return this.service.transcribeExistingRecording(user.sub, id);
  }
  // ─── Hold Music ───

  @Post("rooms/:roomName/hold-music/start")
  @UseGuards(JwtAuthGuard)
  startHoldMusic(@Param("roomName") roomName: string) {
    return this.service.startHoldMusic(roomName);
  }

  @Post("rooms/:roomName/hold-music/stop")
  @UseGuards(JwtAuthGuard)
  stopHoldMusic(@Param("roomName") roomName: string) {
    return this.service.stopHoldMusic(roomName);
  }
}
