import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

function decodeJwtSub(token: string): string {
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
  return payload.sub as string;
}

describe('DeviceKeys (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let user1Token: string;
  let user1Id: string;
  let user2Token: string;
  let user2Id: string;

  const u1Email = `e2e-dk-u1-${Date.now()}@example.test`;
  const u2Email = `e2e-dk-u2-${Date.now()}@example.test`;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
    await app.init();
    prisma = app.get(PrismaService);

    const r1 = await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: u1Email, password: 'P@ssw0rd1!' });
    expect(r1.status).toBe(201);
    user1Token = r1.body.accessToken;
    user1Id = decodeJwtSub(user1Token);

    const r2 = await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: u2Email, password: 'P@ssw0rd2!' });
    expect(r2.status).toBe(201);
    user2Token = r2.body.accessToken;
    user2Id = decodeJwtSub(user2Token);
  });

  afterAll(async () => {
    await prisma.deviceKey.deleteMany({ where: { userId: { in: [user1Id, user2Id] } } });
    await prisma.user.deleteMany({ where: { id: { in: [user1Id, user2Id] } } });
    await app.close();
  });

  const sampleDto = (devicePk: string) => {
    const validUntil = Date.now() + 30 * 86_400_000;
    const userPk = 'c'.repeat(64);
    return {
      devicePk,
      algorithm: 'X25519',
      validUntilEpochMs: validUntil,
      signature: 'f'.repeat(128),
      certificate: JSON.stringify({
        algorithm: 'X25519',
        devicePk,
        userId: 'placeholder',
        userPk,
        validUntilEpochMs: validUntil,
      }),
    };
  };

  it('POST /profile/device-keys — registers a key (201)', async () => {
    const res = await request(app.getHttpServer())
      .post('/profile/device-keys')
      .set('Authorization', `Bearer ${user1Token}`)
      .send(sampleDto('a'.repeat(64)))
      .expect(201);

    expect(res.body.devicePk).toBe('a'.repeat(64));
    expect(res.body.revokedAt).toBeNull();
    expect(res.body.userId).toBe(user1Id);
    expect(res.body.userPk).toBe('c'.repeat(64));
  });

  it('GET /profile/contacts/:userId/keys — returns registered key', async () => {
    const res = await request(app.getHttpServer())
      .get(`/profile/contacts/${user1Id}/keys`)
      .set('Authorization', `Bearer ${user2Token}`)
      .expect(200);

    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body[0].devicePk).toBe('a'.repeat(64));
    expect(res.body[0].userPk).toBe('c'.repeat(64));
  });

  it('POST /profile/device-keys/:id/revoke — revokes own key', async () => {
    const list = await request(app.getHttpServer())
      .get(`/profile/contacts/${user1Id}/keys`)
      .set('Authorization', `Bearer ${user1Token}`)
      .expect(200);

    const keyId = list.body[0].id;

    await request(app.getHttpServer())
      .post(`/profile/device-keys/${keyId}/revoke`)
      .set('Authorization', `Bearer ${user1Token}`)
      .send({ reason: 'e2e test' })
      .expect(201);

    const after = await request(app.getHttpServer())
      .get(`/profile/contacts/${user1Id}/keys`)
      .set('Authorization', `Bearer ${user2Token}`)
      .expect(200);

    expect(after.body.find((k: any) => k.id === keyId)).toBeUndefined();
  });

  it('rejects unauthenticated register (401)', async () => {
    await request(app.getHttpServer())
      .post('/profile/device-keys')
      .send(sampleDto('b'.repeat(64)))
      .expect(401);
  });

  it('rejects expired validUntilEpochMs (400)', async () => {
    await request(app.getHttpServer())
      .post('/profile/device-keys')
      .set('Authorization', `Bearer ${user1Token}`)
      .send({
        ...sampleDto('c'.repeat(64)),
        validUntilEpochMs: Date.now() - 1000,
      })
      .expect(400);
  });

  it('rejects revoke of another user\'s key (404)', async () => {
    // Register a key for user2
    const reg = await request(app.getHttpServer())
      .post('/profile/device-keys')
      .set('Authorization', `Bearer ${user2Token}`)
      .send(sampleDto('d'.repeat(64)))
      .expect(201);

    // user1 tries to revoke user2's key — must fail
    await request(app.getHttpServer())
      .post(`/profile/device-keys/${reg.body.id}/revoke`)
      .set('Authorization', `Bearer ${user1Token}`)
      .send({})
      .expect(404);
  });
});
