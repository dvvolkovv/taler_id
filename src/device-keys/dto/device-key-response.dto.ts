export class DeviceKeyResponseDto {
  id: string;
  userId: string;
  devicePk: string;
  userPk: string | null; // Phase 1c
  algorithm: string;
  validUntil: string; // ISO8601
  certificate: string;
  signature: string;
  revokedAt: string | null;
  createdAt: string;
}
