import { Module } from "@nestjs/common";
import { VoiceController } from "./voice.controller";
import { VoiceService } from "./voice.service";
import { FileStorageService } from "../common/file-storage.service";

@Module({
  controllers: [VoiceController],
  providers: [VoiceService, FileStorageService],
})
export class VoiceModule {}
